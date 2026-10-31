package kestrel.rules

import kestrel.rules.SignalKind.KEV_OTHER
import kestrel.rules.SignalKind.KEV_S6
import kestrel.rules.SignalKind.KEV_S6_OLD
import kestrel.rules.SignalKind.NEWS1_URGENT
import kestrel.rules.SignalKind.S1
import kestrel.rules.SignalKind.S1_8
import kestrel.rules.SignalKind.S2A
import kestrel.rules.SignalKind.S2B
import kestrel.rules.SignalKind.S3
import kestrel.rules.SignalKind.S7
import kestrel.rules.SignalKind.S7K
import kestrel.rules.SignalKind.S7K_MAJOR

/**
 * 등급 규칙 v6 (docs/02-alert-rules.md).
 * 조합 하나라도 모두 갖추면 그 등급이다. [CORE]는 클러스터가 핵심 제품군(S6)이라는 뜻의 가상 신호다.
 *
 * v6: 핵심 제품군 밖이라도 실제 악용(KEV)·치명적 CVSS가 보도와 겹치면 알린다. 해외 침해사고(S7)는 🟠로 낮추고,
 * 국내 침해사고는 금융·통신·공공·대규모면 🔴(S7K_MAJOR), 그 밖은 🟠(S7K)다.
 */
object Rules {
    /** 규칙 판. 바뀌면 수집기는 첫 실행처럼 그동안의 이벤트를 알리지 않고 기록만 한다. */
    const val VERSION = "v6.2"
    private enum class Need { CORE }

    private val RED: List<Set<Any>> = listOf(
        setOf(KEV_S6),
        setOf(S2A),
        setOf(S1, S3),
        setOf(S3, Need.CORE),
        setOf(KEV_OTHER, S3),
        setOf(S7K_MAJOR),
    )

    private val ORANGE: List<Set<Any>> = listOf(
        setOf(KEV_S6_OLD),
        setOf(S1, Need.CORE),
        setOf(S1_8, Need.CORE),
        setOf(S2B),
        setOf(NEWS1_URGENT, Need.CORE),
        setOf(KEV_OTHER, NEWS1_URGENT),
        setOf(S1, NEWS1_URGENT),
        setOf(S7),
        setOf(S7K),
    )

    fun levelFor(present: Set<SignalKind>, isCore: Boolean): Level? {
        val have: Set<Any> = if (isCore) present + Need.CORE else present
        return when {
            RED.any { have.containsAll(it) } -> Level.RED
            ORANGE.any { have.containsAll(it) } -> Level.ORANGE
            else -> null
        }
    }
}
