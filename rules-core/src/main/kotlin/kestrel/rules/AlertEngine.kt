package kestrel.rules

import java.time.LocalDate
import java.time.temporal.ChronoUnit

/**
 * 하루 단위 신호 목록을 받아 등급 변화 이벤트를 만든다. 네트워크와 시계를 쓰지 않는 순수 함수다.
 *
 * - 같은 [Signal.clusterKey]의 신호를 모아 [Rules]로 등급을 정한다.
 * - 클러스터의 마지막 신호 뒤 [quietDays]일이 지나면 새 이벤트로 본다.
 * - 등급이 처음 생기거나 올라갈 때 이벤트를 낸다. [periodStart] 이전의 변화는 내지 않되 등급은 기록한다
 *   (판정 기간이 매일 밀리는 수집기에서, 기간 밖으로 나간 첫 알림 때문에 같은 사건을 다시 알리지 않도록).
 * - v5: 이미 🔴인 클러스터라도 KEV에 그 클러스터에서 처음 보는 CVE가 오르면 다시 🔴 이벤트를 낸다([AlertEvent.trigger]).
 *   같은 날 이미 🔴를 알렸으면 다시 내지 않는다.
 *   제품군 클러스터가 이어지는 동안 새 제로데이가 묻히던 결함(docs/07) 때문이다.
 */
class AlertEngine(
    private val coreGroups: Set<String>,
    private val periodStart: LocalDate,
    private val periodEnd: LocalDate,
    private val quietDays: Long = 7,
) {
    private class ClusterState {
        val lastSeen = mutableMapOf<SignalKind, LocalDate>()
        var level: Level? = null
        val cves = HashSet<String>()
        var lastRed: LocalDate? = null
    }

    fun run(signals: List<Signal>): List<AlertEvent> {
        val states = mutableMapOf<String, ClusterState>()
        val events = mutableListOf<AlertEvent>()
        // 같은 날짜 안에서는 입력 순서를 지킨다 (sortedBy는 안정 정렬)
        for (s in signals.sortedBy { it.date }) {
            if (s.date > periodEnd) continue
            var st = states.getOrPut(s.clusterKey) { ClusterState() }
            val latest = st.lastSeen.values.maxOrNull()
            if (latest != null && ChronoUnit.DAYS.between(latest, s.date) > quietDays) {
                st = ClusterState().also { states[s.clusterKey] = it }
            }
            val prev = st.lastSeen[s.kind]
            st.lastSeen[s.kind] = if (prev == null || s.date > prev) s.date else prev

            val level = Rules.levelFor(st.lastSeen.keys, s.clusterKey in coreGroups)
            val newCves = if (s.kind == SignalKind.KEV_S6 || s.kind == SignalKind.KEV_S6_OLD) {
                CVE.findAll(s.detail).map { it.value }.filter { it !in st.cves }.toSortedSet().toList()
            } else {
                emptyList()
            }
            st.cves += newCves
            if (rank(level) > rank(st.level)) {
                st.level = level
                if (level == Level.RED) st.lastRed = s.date
                if (s.date >= periodStart) events += AlertEvent(s.date, s.clusterKey, level!!, st.lastSeen.keys.map { it.code }.sorted())
            } else if (s.kind == SignalKind.KEV_S6 && st.level == Level.RED && newCves.isNotEmpty() && s.date >= periodStart && st.lastRed != s.date) {
                // 같은 날 이미 🔴를 알렸으면 CVE만 기록한다(KEV가 같은 제품 CVE를 한꺼번에 올리는 경우)
                st.lastRed = s.date
                events += AlertEvent(s.date, s.clusterKey, Level.RED, st.lastSeen.keys.map { it.code }.sorted(), trigger = newCves.first())
            }
        }
        return events
    }

    private companion object {
        val CVE = Regex("""CVE-\d{4}-\d{4,7}""")
    }

    private fun rank(level: Level?): Int = when (level) {
        null -> 0
        Level.ORANGE -> 1
        Level.RED -> 2
    }
}
