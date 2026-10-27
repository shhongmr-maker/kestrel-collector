package kestrel.collector

import kestrel.rules.Level
import org.json.JSONObject
import org.json.JSONStringer
import java.net.URLEncoder
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.time.Instant
import java.util.Base64

/** Firebase 서비스 계정 키(JSON)에서 쓰는 값. */
data class ServiceAccount(val projectId: String, val clientEmail: String, val privateKey: PrivateKey, val tokenUri: String) {
    companion object {
        fun parse(json: String): ServiceAccount {
            val o = JSONObject(json)
            val pem = o.getString("private_key")
                .replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace(Regex("\\s"), "") // gitleaks:allow pragma: allowlist secret (PEM 머리말 문자열, 키 아님)
            val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)))
            return ServiceAccount(
                o.getString("project_id"), o.getString("client_email"), key,
                o.optString("token_uri", "https://oauth2.googleapis.com/token"),
            )
        }
    }
}

/**
 * 발송 방식.
 * - [V1_HIGH]: `android.priority = HIGH`인 데이터 메시지. 앱이 알림을 직접 만든다(🔴 반복, 잠금 화면 공개 범위). 정식 지원.
 * - [V2_REMOTE_NOTIFICATION]: `android_v2.remote_notification`. 배터리 절약을 건너뛰고 바로 전달된다고 문서에 적혀 있으나
 *   2026-10-26 기준 미리보기(Pre-GA)이고, 앱 쪽 SDK도 EAP뿐이다. 실제 기기 시험 뒤 고른다.
 */
enum class FcmMode { V1_HIGH, V2_REMOTE_NOTIFICATION }

/**
 * 받는 기기. firebase-messaging 25.1.0부터 등록 토큰(getToken/onNewToken)은 지원 중단 예정이고,
 * 앱은 register() → onRegistered(FID)로 받은 Firebase 설치 ID(FID)를 쓴다. REST의 message.fid로 보낸다.
 * 예전 등록 토큰도 당분간 받는다(message.token).
 */
data class FcmTarget(val fid: Boolean, val value: String) {
    val suffix: String get() = value.takeLast(6)

    companion object {
        fun parse(fids: String?, tokens: String?): List<FcmTarget> =
            split(fids).map { FcmTarget(true, it) } + split(tokens).map { FcmTarget(false, it) }

        private fun split(s: String?) = s.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }
}

/** FCM HTTP v1 API 발송. 서비스 계정으로 OAuth 토큰을 받아(1시간 유효) 등록 토큰마다 보낸다. */
class FcmSender(
    private val account: ServiceAccount,
    private val http: Poster,
    private val mode: FcmMode = FcmMode.V1_HIGH,
    private val fcmBase: String = "https://fcm.googleapis.com",
    private val clock: () -> Instant = Instant::now,
) {
    companion object {
        const val SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
        /** 기기가 꺼져 있을 때 FCM이 보관하는 시간. 하루 지난 긴급 알림은 feed로 보면 되므로 길게 두지 않는다. */
        val TTL: Duration = Duration.ofHours(24)
        private val B64 = Base64.getUrlEncoder().withoutPadding()

        fun levelLabel(level: Level) = if (level == Level.RED) "🔴 즉시 확인" else "🟠 주목"

        /** 푸시 본문: 근거 신호 중 마지막 것의 설명(최대 120자). 상세는 feed에서 본다. */
        fun body(e: FeedEvent): String =
            (e.headline.ifEmpty { null } ?: e.evidence.lastOrNull()?.detail ?: e.signals.joinToString(", ")).let {
                // 코드 포인트 단위로 자른다(이모지 등 서로게이트 쌍이 반으로 잘려 JSON이 깨지지 않게)
                if (it.codePointCount(0, it.length) > 120) it.takeCodePoints(119) + "…" else it
            }

        fun title(e: FeedEvent): String =
            (if (e.isFollowUp) "추가 보도 · " else "${levelLabel(e.level)} · ") + e.title.ifEmpty { e.clusterKey + if (e.trigger.isNotEmpty()) " (${e.trigger})" else "" }.let {
                if (it.codePointCount(0, it.length) > 80) it.takeCodePoints(79) + "…" else it
            }
    }

    private var cached: Pair<String, Instant>? = null

    /** RS256으로 서명한 JWT. exp는 발급 뒤 1시간이 최대다. */
    fun jwt(now: Instant): String {
        val header = """{"alg":"RS256","typ":"JWT"}"""
        val claims = JSONStringer().`object`()
            .key("iss").value(account.clientEmail).key("scope").value(SCOPE).key("aud").value(account.tokenUri)
            .key("iat").value(now.epochSecond).key("exp").value(now.epochSecond + 3600).endObject().toString()
        val input = B64.encodeToString(header.toByteArray()) + "." + B64.encodeToString(claims.toByteArray())
        val sig = Signature.getInstance("SHA256withRSA").apply { initSign(account.privateKey); update(input.toByteArray()) }.sign()
        return input + "." + B64.encodeToString(sig)
    }

    fun accessToken(): String {
        val now = clock()
        cached?.let { (token, expires) -> if (now.isBefore(expires.minusSeconds(60))) return token }
        val body = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", Charsets.UTF_8) +
            "&assertion=" + jwt(now)
        val res = http.post(account.tokenUri, mapOf("Content-Type" to "application/x-www-form-urlencoded"), body)
        if (res.status != 200) throw SourceFetchException("FCM 인증", "HTTP ${res.status}: ${res.body.take(200)}")
        val o = JSONObject(res.body)
        val token = o.getString("access_token")
        cached = token to now.plusSeconds(o.optLong("expires_in", 3600))
        return token
    }

    /** 메시지 본문(JSON). 데이터 값은 모두 문자열이어야 한다. */
    fun message(target: FcmTarget, e: FeedEvent, feedSha: String): String {
        val data = linkedMapOf(
            "id" to e.id, "level" to e.level.name, "cluster" to e.clusterKey, "date" to e.date.toString(),
            "trigger" to e.trigger, "title" to title(e), "body" to body(e), "feedSha" to feedSha,
        )
        // 추가 보도: 앱이 무음으로 띄우고, 누르면 처음 알린 이벤트(ref)의 상세를 연다
        if (e.isFollowUp) { data["kind"] = "followup"; data["ref"] = e.ref }
        val w = JSONStringer().`object`().key("message").`object`().key(if (target.fid) "fid" else "token").value(target.value)
        w.key("data").`object`(); data.forEach { (k, v) -> w.key(k).value(v) }; w.endObject()
        when (mode) {
            FcmMode.V1_HIGH -> w.key("android").`object`().key("priority").value("HIGH").key("ttl").value("${TTL.seconds}s").endObject()
            FcmMode.V2_REMOTE_NOTIFICATION -> w.key("android_v2").`object`()
                .key("ttl").value("${TTL.seconds}s")
                .key("remote_notification").`object`()
                .key("notification").`object`()
                .key("title").value(title(e)).key("body").value(body(e)).key("tag").value(e.id)
                .key("channel_id").value(if (e.level == Level.RED) "red" else "orange")
                .key("visibility").value("PRIVATE")
                .endObject().endObject().endObject()
        }
        return w.endObject().endObject().toString()
    }

    /** 결과: 성공이면 FCM 메시지 이름, 실패면 상태 코드와 FCM 오류 코드(예: UNREGISTERED). */
    data class Result(val tokenSuffix: String, val eventId: String, val ok: Boolean, val detail: String)

    fun send(targets: List<FcmTarget>, events: List<FeedEvent>, feedSha: String): List<Result> {
        if (targets.isEmpty() || events.isEmpty()) return emptyList()
        val auth = mapOf("Authorization" to "Bearer ${accessToken()}", "Content-Type" to "application/json; charset=UTF-8")
        val url = "$fcmBase/v1/projects/${account.projectId}/messages:send"
        // 🔴를 먼저 보낸다
        val ordered = events.sortedWith(compareByDescending<FeedEvent> { it.level }.thenBy { it.date })
        return targets.flatMap { target ->
            ordered.map { e ->
                val suffix = target.suffix
                // 메시지 하나가 실패해도 나머지는 계속 보낸다
                val res = try {
                    http.post(url, auth, message(target, e, feedSha))
                } catch (ex: Exception) {
                    return@map Result(suffix, e.id, false, "error ${ex.javaClass.simpleName}: ${ex.message}".take(200))
                }
                if (res.status == 200) {
                    Result(suffix, e.id, true, runCatching { JSONObject(res.body).optString("name") }.getOrDefault(""))
                } else {
                    val code = runCatching {
                        JSONObject(res.body).getJSONObject("error").optJSONArray("details")?.let { d ->
                            (0 until d.length()).map { d.getJSONObject(it) }.firstNotNullOfOrNull { it.optString("errorCode").ifEmpty { null } }
                        } ?: JSONObject(res.body).getJSONObject("error").optString("status")
                    }.getOrNull() ?: ""
                    Result(suffix, e.id, false, "HTTP ${res.status} $code".trim())
                }
            }
        }
    }
}
