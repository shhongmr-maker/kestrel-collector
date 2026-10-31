package kestrel.collector

import kestrel.rules.AlertEvent
import kestrel.rules.Level
import kestrel.rules.Signal
import java.time.Instant
import java.time.LocalDate

/** 앱이 받는 public/feed.json. 공개 정보만 담는다(자산 정보 없음). [appAdvisory]는 선택 항목이라 스키마 1 그대로다. */
data class Feed(
    val generatedAt: Instant,
    val sources: List<FeedSource>,
    val events: List<FeedEvent>,
    val appAdvisory: AppAdvisory? = null,
    /** 이벤트 클러스터별 상세(제목·CVE·영향 범위·근거 문서). 0.3.x 앱은 모르는 필드라 무시한다. */
    val clusters: Map<String, ClusterDetail> = emptyMap(),
    val incidents: List<IncidentInfo> = emptyList(),
    val notices: List<NoticeInfo> = emptyList(),
    val briefs: List<BriefInfo> = emptyList(),
) {
    companion object {
        const val SCHEMA = 1
    }
}

/**
 * Kestrel 앱 자신에 대한 보안 공지. 앱에서 취약점이 발견되면 수집기 저장소의 config/app-advisory.json을 채운다.
 * 앱의 versionCode가 [minVersionCode]보다 낮으면 "업데이트 필요"를 띄운다.
 */
data class AppAdvisory(val minVersionCode: Int, val message: String, val url: String?) {
    companion object {
        fun parse(json: String): AppAdvisory {
            val o = org.json.JSONObject(json)
            val min = o.getInt("minVersionCode")
            val message = o.getString("message").trim()
            val url = o.optString("url", "").trim().ifEmpty { null }
            require(min >= 1) { "minVersionCode는 1 이상" }
            require(message.isNotEmpty() && message.length <= 300) { "message는 1~300자" }
            require(url == null || url.startsWith("https://")) { "url은 https만" }
            return AppAdvisory(min, message, url)
        }
    }
}

data class FeedSource(
    val name: String,
    val ok: Boolean,
    val lastSuccessAt: Instant?,
    val lastAttemptAt: Instant?,
    val error: String?,
    val warning: String?,
) {
    companion object {
        fun of(name: String, s: SourceState) =
            FeedSource(name, s.error == null && s.lastSuccessAt != null, s.lastSuccessAt, s.lastAttemptAt, s.error, s.warning)
    }
}

/** 판정 이벤트 하나와 그 근거 신호. [id]는 날짜·클러스터·등급·재알림 CVE로 정해지므로 실행마다 같다. [trigger]가 있으면 KEV 새 CVE 재알림이다. */
data class FeedEvent(
    val id: String,
    val date: LocalDate,
    val clusterKey: String,
    val level: Level,
    val signals: List<String>,
    val trigger: String,
    val firstSeen: Instant,
    val evidence: List<Signal>,
    /** 규칙으로 만든 한국어 제목(예: "PHP 치명적 원격 취약점 (CVSS 9.2)"). */
    val title: String = "",
    /** 대표 원문 제목(KISA 공지나 기사). */
    val headline: String = "",
    /** 추가 보도 알림([isFollowUp])이면 처음 알린 이벤트의 id, [relation]이 있으면 먼저 알린 같은 위협의 이벤트 id */
    val ref: String = "",
    /**
     * 먼저 알린 같은 위협(같은 클러스터이거나 CVE가 겹침, [Collector.RELATED_WINDOW] 안)과의 관계. 판정과 무관하게 알리는 방식만 바꾼다.
     * - [UPGRADE]: 🟠로 알린 위협이 🔴가 됨, [REPEAT]: 🔴로 알린 위협이 다시 🔴(예: KEV 등재). 앱은 반복하지 않고 한 번 진동한다
     * - [UPDATE]: 알린 침해사고의 후속 보도(피해 규모 확대 등). 앱은 무음으로 띄운다
     */
    val relation: String = "",
) {
    /** 이미 알린 취약점의 추가 보도(무음 알림). 판정 이벤트가 아니며 feed에는 싣지 않는다 */
    val isFollowUp: Boolean get() = trigger == FOLLOWUP
    val isEscalation: Boolean get() = relation == UPGRADE || relation == REPEAT

    companion object {
        const val FOLLOWUP = "FOLLOWUP"
        const val UPGRADE = "UPGRADE"
        const val REPEAT = "REPEAT"
        const val UPDATE = "UPDATE"

        fun of(e: AlertEvent, firstSeen: Instant, evidence: List<Signal>, titles: Pair<String, String> = "" to "") =
            FeedEvent(
                listOf(e.date, e.clusterKey, e.level, e.trigger).filter { it.toString().isNotEmpty() }.joinToString("|"),
                e.date, e.clusterKey, e.level, e.signals, e.trigger, firstSeen, evidence, titles.first, titles.second,
            )
    }
}
