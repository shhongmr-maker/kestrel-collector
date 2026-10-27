package kestrel.rules

import java.time.LocalDate

/** 판정에 쓰는 신호 종류. [code]는 research/의 Python 엔진과 같은 문자열이다. */
enum class SignalKind(val code: String) {
    KEV_S6("KEV_S6"),             // 핵심 제품군(S6)의 KEV 등재
    KEV_S6_OLD("KEV_S6_OLD"),     // 공개 2년이 넘은 CVE의 KEV 등재 (선택 옵션)
    KEV_OTHER("KEV_OTHER"),       // 그 외 KEV 등재
    S1("S1"),                     // CVSS >= 9.0, AV:N/PR:N/UI:N 또는 체인 규칙
    S1_8("S1_8"),                 // CVSS >= 8.0, AV:N/PR:N
    S2A("S2a"),                   // KISA 강한 비정례 공지
    S2B("S2b"),                   // KISA 주의 권고
    S2C("S2c"),                   // KISA 피싱·사칭 주의보
    KISA_ROUTINE("KISA_ROUTINE"), // KISA 정례 공지
    S3("S3"),                     // 매체 보도 급증
    NEWS1_URGENT("NEWS1_URGENT"), // 긴급 표현이 있는 기사 (키마다 하루 한 번)
    S7("S7"),                     // 해외 침해사고 보도(두 매체)
    S7K("S7K"),                   // 국내 침해사고 보도(v6, 한국 매체)
    S7K_MAJOR("S7K_MAJOR");       // 국내 침해사고 중 금융·통신·공공·대규모(v6)

    companion object {
        private val byCode = entries.associateBy { it.code }
        fun fromCode(code: String): SignalKind = byCode[code] ?: error("알 수 없는 신호: $code")
    }
}

enum class Level { ORANGE, RED }

/** 하루 단위로 들어오는 신호 하나. [clusterKey]는 제품군 이름, CVE 번호, KISA 제목 등이다. */
data class Signal(val date: LocalDate, val clusterKey: String, val kind: SignalKind, val detail: String = "")

/**
 * 등급이 처음 생기거나 올라간 순간, 또는 이미 🔴인 클러스터에 KEV 새 CVE가 오른 순간.
 * [signals]는 그 시점에 클러스터에 있던 신호의 code를 정렬한 것이다.
 * [trigger]는 재알림일 때 그 CVE 번호이고, 등급 변화일 때는 빈 문자열이다.
 */
data class AlertEvent(
    val date: LocalDate,
    val clusterKey: String,
    val level: Level,
    val signals: List<String>,
    val trigger: String = "",
)
