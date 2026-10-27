package kestrel.collector

import java.io.File
import java.time.Instant
import kotlin.system.exitProcess

private const val USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) kestrel-collector"

/**
 * 수집기 명령.
 *
 * - `collect --state <state.json> --feed <feed.json> [--alerts <new-alerts.json>] [--advisory <app-advisory.json>]`
 *   --advisory 파일이 있으면 앱 보안 공지를 feed에 싣는다(없으면 건너뜀).
 *   소스를 받아 판정하고 state·feed·새 알림 목록을 쓴다. NVD API 키는 환경 변수 NVD_API_KEY.
 *   소스가 실패해도 종료 코드는 0이다(실패는 feed의 sources에 기록).
 * - `push --alerts <new-alerts.json> --feed-sha <커밋 SHA> --status <push-status.json>`
 *   새 알림을 FCM으로 보낸다. 환경 변수: FCM_SERVICE_ACCOUNT(서비스 계정 키 JSON 내용), FCM_FIDS(쉼표로 구분한 기기 FID),
 *   FCM_TOKENS(예전 등록 토큰, 선택),
 *   FCM_MODE(v1 기본, v2는 미리보기). 보낼 알림이 없으면 아무것도 하지 않는다. 하나라도 실패하면 종료 코드 1.
 * - `requeue --state <state.json> --alerts <new-alerts.json> --status <push-status.json>`
 *   push가 일시적인 이유로 보내지 못한 알림을 state의 "알린 것"에서 빼 다음 실행이 다시 보내게 한다(Requeue).
 * - `test-push --status <push-status.json>`
 *   설치 확인용 시험 알림(🔴) 하나를 보낸다. 환경 변수는 push와 같다.
 */
fun main(args: Array<String>) {
    val cmd = args.firstOrNull() ?: usage()
    val opts = args.drop(1).windowed(2, 2).associate { (k, v) -> k to v }
    when (cmd) {
        "collect" -> collect(opts)
        "push" -> exitProcess(push(opts))
        "test-push" -> exitProcess(testPush(opts))
        "requeue" -> requeue(opts)
        else -> usage()
    }
}

private fun collect(opts: Map<String, String>) {
    val stateFile = File(opts["--state"] ?: usage())
    val feedFile = File(opts["--feed"] ?: usage())
    val alertsFile = opts["--alerts"]?.let(::File)

    val key = DataKey.fromEnv()
    val prev = if (stateFile.exists()) Json.readState(DataKey.readState(stateFile.readText(), key)) else CollectorState()
    val collector = Collector(Sources(JdkFetcher(USER_AGENT), System.getenv("NVD_API_KEY")?.takeIf { it.isNotBlank() }))
    val advisory = opts["--advisory"]?.let(::File)?.takeIf { it.exists() }?.let { AppAdvisory.parse(it.readText()) }
    val result = collector.run(prev, Instant.now()).let { it.copy(feed = it.feed.copy(appAdvisory = advisory)) }

    stateFile.parentFile?.mkdirs(); stateFile.writeText(DataKey.writeState(Json.writeState(result.state) + "\n", key))
    val feedBytes = (Json.writeFeed(result.feed) + "\n").toByteArray()
    feedFile.parentFile?.mkdirs(); feedFile.writeBytes(feedBytes)
    // 앱은 이 서명이 있는 feed만 믿는다(공개 키는 앱에 고정). 키가 없으면 서명하지 않는다
    key?.let { File(feedFile.path + ".sig").writeText(it.sign(feedBytes) + "\n") }
    println(if (key != null) "feed 서명·state 암호화: 켬" else "feed 서명·state 암호화: 끔(${DataKey.ENV} 없음)")
    alertsFile?.let { it.parentFile?.mkdirs(); it.writeText(Json.writeEvents(result.newAlerts) + "\n") }

    for (s in result.feed.sources) {
        println("source ${s.name}: ${if (s.ok) "ok" else "FAIL"}${s.error?.let { " — $it" } ?: ""}${s.warning?.let { " (주의: $it)" } ?: ""}")
    }
    println("events(feed ${result.feed.events.size}) new alerts ${result.newAlerts.size}")
    for (a in result.newAlerts) println("NEW ${a.level} ${a.date} ${a.clusterKey} ${a.signals} ${a.trigger}")
}

private fun requeue(opts: Map<String, String>) {
    val stateFile = File(opts["--state"] ?: usage())
    val alertsFile = File(opts["--alerts"] ?: usage())
    val statusFile = File(opts["--status"] ?: usage())
    if (!stateFile.exists() || !alertsFile.exists()) return println("requeue: state 또는 새 알림 파일 없음, 건너뜀")
    val alerts = Json.readEvents(alertsFile.readText())
    if (alerts.isEmpty()) return println("requeue: 새 알림 없음")
    val (results, error) = if (statusFile.exists()) Json.readPushStatus(statusFile.readText()) else emptyList<FcmSender.Result>() to "push-status 없음"
    val key = DataKey.fromEnv()
    val out = Requeue.apply(Json.readState(DataKey.readState(stateFile.readText(), key)), alerts, results, error, java.time.LocalDate.now(java.time.ZoneOffset.UTC))
    stateFile.writeText(DataKey.writeState(Json.writeState(out.state) + "\n", key))
    println(if (out.requeued.isEmpty()) "requeue: 다시 보낼 알림 없음" else "requeue: 다음 실행에서 다시 보냄 ${out.requeued}")
}

/** 설치 확인용 시험 알림. 앱의 알림 id 형식(날짜|클러스터|등급)을 따른다. */
fun testAlert(now: Instant): FeedEvent {
    val date = now.atZone(java.time.ZoneOffset.UTC).toLocalDate()
    return FeedEvent(
        id = "$date|TEST|RED", date = date, clusterKey = "TEST", level = kestrel.rules.Level.RED, signals = emptyList(),
        trigger = "", firstSeen = now,
        evidence = listOf(kestrel.rules.Signal(date, "TEST", kestrel.rules.SignalKind.S3, "Kestrel 시험 알림이다. 이 알림이 소리와 함께 보이면 설치가 끝났다")),
    )
}

private fun testPush(opts: Map<String, String>): Int {
    val statusFile = File(opts["--status"] ?: usage())
    val alertsFile = File.createTempFile("kestrel-test", ".json").apply { deleteOnExit(); writeText(Json.writeEvents(listOf(testAlert(Instant.now())))) }
    return push(mapOf("--alerts" to alertsFile.path, "--feed-sha" to "data", "--status" to statusFile.path))
}

private fun push(opts: Map<String, String>): Int {
    val alerts = Json.readEvents(File(opts["--alerts"] ?: usage()).readText())
    val feedSha = opts["--feed-sha"] ?: usage()
    val statusFile = File(opts["--status"] ?: usage())
    if (alerts.isEmpty()) {
        println("보낼 알림 없음")
        return 0
    }
    val targets = FcmTarget.parse(System.getenv("FCM_FIDS"), System.getenv("FCM_TOKENS"))
    val account = System.getenv("FCM_SERVICE_ACCOUNT")?.takeIf { it.isNotBlank() }
    val mode = if (System.getenv("FCM_MODE") == "v2") FcmMode.V2_REMOTE_NOTIFICATION else FcmMode.V1_HIGH
    val (results, error) = if (account == null || targets.isEmpty()) {
        emptyList<FcmSender.Result>() to Requeue.NO_SECRETS
    } else {
        try {
            FcmSender(ServiceAccount.parse(account), JdkFetcher(USER_AGENT), mode).send(targets, alerts, feedSha) to null
        } catch (e: Exception) {
            emptyList<FcmSender.Result>() to (e.message ?: e.javaClass.simpleName)
        }
    }
    statusFile.parentFile?.mkdirs(); statusFile.writeText(Json.writePushStatus(Instant.now(), results, error) + "\n")
    for (r in results) println("push ${r.eventId} → …${r.tokenSuffix}: ${if (r.ok) "ok" else "FAIL ${r.detail}"}")
    error?.let { System.err.println("push 실패: $it") }
    return if (error == null && results.all { it.ok }) 0 else 1
}

private fun usage(): Nothing {
    System.err.println(
        "사용법:\n  collect --state <state.json> --feed <feed.json> [--alerts <new-alerts.json>] [--advisory <app-advisory.json>]\n" +
            "  push --alerts <new-alerts.json> --feed-sha <sha> --status <push-status.json>\n" +
            "  requeue --state <state.json> --alerts <new-alerts.json> --status <push-status.json>\n" +
            "  test-push --status <push-status.json>",
    )
    exitProcess(2)
}
