package kestrel.rules

import java.time.LocalDate

/**
 * 제조사 보안 공지 하나(v6.3). [date]는 게시일과 수정일 중 늦은 날(UTC)이다. 실제 악용 문구가 수정으로 더해지는 경우가 있어서다.
 * [text]는 공지 요약(일반 텍스트)이고, [exploited]는 제조사가 구조화된 값(CVSS 위협 지표 E:A 등)으로 밝힌 경우에만 채운다.
 */
data class VendorAdvisory(
    val vendor: String,
    val date: LocalDate,
    val title: String,
    val text: String,
    val cves: List<String> = emptyList(),
    val exploited: Boolean? = null,
)

/**
 * 공지 문장에서 "실제 악용 확인"을 찾는다. 같은 문장에 부정(not·no evidence·unaware)이 있으면 악용으로 보지 않는다.
 * 실제 문구(2026-11 확인): Fortinet "This has been reported to be exploited in the wild",
 * Ivanti "Ivanti is aware of limited exploitation in the wild" / "not aware of exploitation in the wild",
 * Palo Alto "Very limited exploitation has been observed" / "not aware of any malicious exploitation",
 * Cisco "not known to be actively exploited".
 */
object VendorExploit {
    private val POSITIVE = Regex(
        "exploited in the wild|exploitation in the wild|actively exploited|under active exploitation|" +
            "\\baware of .{0,40}(exploitation|exploit attempts|malicious use|attacks? (against|targeting|exploiting))|" +
            "exploitation (has been|was|is being|have been) observed|observed .{0,30}exploitation|" +
            "(has|have) been (reported to be )?exploited|being exploited|limited number of customers",
        RegexOption.IGNORE_CASE,
    )
    private val NEGATIVE = Regex("\\bnot\\b|\\bno (evidence|known|indication|reports?)\\b|\\bunaware\\b|n't\\b|\\bnever\\b", RegexOption.IGNORE_CASE)
    private val SENTENCE = Regex("(?<=[.!?])\\s+|\\n+|•")

    fun inText(text: String): Boolean = text.split(SENTENCE).any { POSITIVE.containsMatchIn(it) && !NEGATIVE.containsMatchIn(it) }

    fun of(a: VendorAdvisory): Boolean = a.exploited ?: inText(a.title + ". " + a.text)
}
