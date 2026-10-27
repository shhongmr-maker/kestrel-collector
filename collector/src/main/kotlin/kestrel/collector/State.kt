package kestrel.collector

import kestrel.rules.Article
import kestrel.rules.KevEntry
import kestrel.rules.KisaPost
import kestrel.rules.Level
import kestrel.rules.NvdCve
import java.time.Instant
import java.time.LocalDate

/** 수집기가 처음 본 시각([firstSeen])을 붙인 항목. 출처가 적은 시각은 틀릴 때가 있어 따로 기록한다. */
data class Seen<T>(val value: T, val url: String, val firstSeen: Instant)

/** 소스별 마지막 시도·성공과 이어 받기 위치. [cursor]의 뜻은 소스마다 다르다(KEV: Last-Modified, 나머지: 마지막 성공 시각). */
data class SourceState(
    val lastAttemptAt: Instant? = null,
    val lastSuccessAt: Instant? = null,
    val error: String? = null,
    val warning: String? = null,
    val cursor: String? = null,
)

/** 이미 알린 이벤트. 같은 클러스터·등급·[trigger](KEV 새 CVE 재알림이면 그 CVE)를 다시 알리지 않기 위해 둔다. */
data class Notified(val date: LocalDate, val clusterKey: String, val level: Level, val firstSeen: Instant, val trigger: String = "")

/**
 * 실행 사이에 이어지는 상태(state/state.json). 원자료는 판정 창(기본 30일) 안의 것만 남긴다.
 * [initialized]가 false인 첫 실행, 그리고 [rulesVersion]이 지금 규칙 판과 다른 실행은
 * 그때까지의 이벤트를 알리지 않고 알린 것으로만 기록한다(규칙이 바뀌어 과거 이벤트가 새로 생기는 것을 막는다).
 */
data class CollectorState(
    val initialized: Boolean = false,
    val rulesVersion: String = "",
    val sources: Map<String, SourceState> = emptyMap(),
    val kev: List<Seen<KevEntry>> = emptyList(),
    val nvd: List<Seen<NvdCve>> = emptyList(),
    val kisa: List<Seen<KisaPost>> = emptyList(),
    val news: List<Seen<Article>> = emptyList(),
    val notified: List<Notified> = emptyList(),
    /** 보호나라 본문 받기 실패 횟수(링크별). [Collector.KISA_BODY_TRIES]번 실패하면 더 받지 않는다. */
    val bodyFailures: Map<String, Int> = emptyMap(),
    /** 추가 보도 알림을 마지막으로 보낸 시각(클러스터별). [Collector.FOLLOWUP_GAP]보다 자주 보내지 않는다 */
    val followups: Map<String, Instant> = emptyMap(),
)
