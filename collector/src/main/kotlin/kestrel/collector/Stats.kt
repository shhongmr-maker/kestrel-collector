package kestrel.collector

import kestrel.rules.Level
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

/**
 * 하루(한국 날짜) 운영 집계. 원자료·개인 정보 없이 수만 센다. 앱의 운영 통계 화면과 운영 검토에 쓴다.
 * [maxGapMin]: 그날 끝난 실행 간격 중 가장 긴 것(분). [sourceErrors]: 실패한 소스 수의 합(실행마다).
 */
data class DayStats(
    val date: LocalDate,
    val runs: Int = 0,
    val maxGapMin: Int = 0,
    val red: Int = 0,
    val orange: Int = 0,
    val upgrade: Int = 0,
    val repeat: Int = 0,
    val update: Int = 0,
    val followups: Int = 0,
    val pushOk: Int = 0,
    val pushFail: Int = 0,
    val sourceErrors: Int = 0,
)

/** 실행 사이에 이어지는 집계(state 안). 30일만 남기고, feed에는 최근 14일을 싣는다 */
data class RunStats(val lastRunAt: Instant? = null, val days: List<DayStats> = emptyList()) {
    companion object {
        const val KEEP_DAYS = 30L
        const val FEED_DAYS = 14L
        val KST: ZoneOffset = ZoneOffset.ofHours(9)

        fun dayOf(now: Instant): LocalDate = now.atZone(KST).toLocalDate()
    }

    private fun change(d: LocalDate, f: (DayStats) -> DayStats) = copy(
        days = (days.filter { it.date != d } + f(days.firstOrNull { it.date == d } ?: DayStats(d)))
            .filter { it.date > d.minusDays(KEEP_DAYS) }.sortedBy { it.date },
    )

    /** 수집 한 번: 실행 수·간격, 이번에 보낼 알림(등급·관계·추가 보도), 실패한 소스 수 */
    fun afterRun(now: Instant, alerts: List<FeedEvent>, failedSources: Int): RunStats {
        val gap = lastRunAt?.let { Duration.between(it, now).toMinutes().toInt().coerceAtLeast(0) } ?: 0
        val events = alerts.filterNot { it.isFollowUp }
        return change(dayOf(now)) { s ->
            s.copy(
                runs = s.runs + 1,
                maxGapMin = maxOf(s.maxGapMin, gap),
                red = s.red + events.count { it.level == Level.RED },
                orange = s.orange + events.count { it.level == Level.ORANGE },
                upgrade = s.upgrade + events.count { it.relation == FeedEvent.UPGRADE },
                repeat = s.repeat + events.count { it.relation == FeedEvent.REPEAT },
                update = s.update + events.count { it.relation == FeedEvent.UPDATE },
                followups = s.followups + alerts.count { it.isFollowUp },
                sourceErrors = s.sourceErrors + failedSources,
            )
        }.copy(lastRunAt = now)
    }

    /** 푸시 결과(requeue 단계에서): 기기별 성공·실패 수 */
    fun afterPush(now: Instant, ok: Int, fail: Int): RunStats =
        if (ok == 0 && fail == 0) this else change(dayOf(now)) { it.copy(pushOk = it.pushOk + ok, pushFail = it.pushFail + fail) }

    /** feed에 실을 최근 [FEED_DAYS]일 */
    fun recent(now: Instant): List<DayStats> = dayOf(now).minusDays(FEED_DAYS).let { from -> days.filter { it.date > from } }
}
