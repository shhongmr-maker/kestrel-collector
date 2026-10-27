package kestrel.rules

import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

/** 뉴스 기사 하나. [source]는 매체 식별자(예: "THN", "BC", 한국어 "DS"), [publishedAt]은 UTC 시각이다. */
data class Article(val source: String, val publishedAt: Instant, val title: String, val text: String = "")

object UrgentText {
    private val URGENT = Regex(
        "zero[- ]day|0-day|actively exploited|exploited in (the wild|attacks)|exploit(ed|s)? (in|to)|under (active )?attack|" +
            "emergency|backdoor|\\bRCE\\b|remote code execution|mass exploitation|hackers? (exploit|target|abuse)|" +
            "now exploited|exploitation|in attacks|critical .{0,40}(flaw|bug|vulnerabilit)|" +
            // v5: 'attackers exploit …' 문형을 놓치던 것을 보강
            "(attackers?|threat actors?) (now )?(exploit|target|abuse)",
        RegexOption.IGNORE_CASE,
    )

    /** 한국어 매체(데일리시큐). 긴급 표현은 제목만 보고, 칼럼·연재는 뺀다(v6). */
    const val KOREAN_SOURCE = "DS"
    private val URGENT_KO = Regex(
        "긴급|제로데이|0-?day|실제 (공격|악용)|악용 (중|확인|시도|정황)|악용되|공격에 악용|대규모 (공격|악용)|" +
            "원격 ?(코드|명령) ?실행|인증 없이|서버 장악|즉시 (패치|업데이트)|패치 서둘러",
        RegexOption.IGNORE_CASE,
    )
    private val NOT_URGENT_KO = Regex("칼럼|기고|연재|소설|인터뷰|웨비나|세미나|컨퍼런스|콘퍼런스")

    /** 제목, 또는 본문 앞 300자에 긴급·위험 표현이 있는가. 한국어 매체는 제목만 본다. */
    fun isUrgent(a: Article): Boolean = if (a.source == KOREAN_SOURCE) {
        URGENT_KO.containsMatchIn(a.title) && !NOT_URGENT_KO.containsMatchIn(a.title)
    } else {
        URGENT.containsMatchIn(a.title) || URGENT.containsMatchIn(a.text.takeCodePoints(300))
    }
}

/**
 * S3(매체 보도 급증): 같은 클러스터 기사들 중 24시간 창 안에
 * 서로 다른 매체 2곳 이상 또는 같은 매체 3건 이상이 있고, 그중 하나라도 긴급 표현이 있으면 성립한다.
 *
 * S3 시각은 조건이 **처음 충족된 기사**의 시각이다. (창의 마지막 기사 시각으로 잡으면 하루 늦어지는 버그가 있었다)
 */
object NewsBurst {
    private val WINDOW: Duration = Duration.ofHours(24)

    fun firstBurst(articles: List<Article>): Article? {
        val sorted = articles.sortedBy { it.publishedAt }
        for ((j, a) in sorted.withIndex()) {
            val window = sorted.subList(0, j + 1).filter { Duration.between(it.publishedAt, a.publishedAt) <= WINDOW }
            val bySource = window.groupingBy { it.source }.eachCount()
            val enoughCoverage = bySource.size >= 2 || bySource.values.max() >= 3
            if (enoughCoverage && window.any(UrgentText::isUrgent)) return a
        }
        return null
    }

    fun firstBurstDate(articles: List<Article>): LocalDate? =
        firstBurst(articles)?.publishedAt?.atZone(ZoneOffset.UTC)?.toLocalDate()
}
