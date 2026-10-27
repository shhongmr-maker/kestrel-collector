package kestrel.collector

import kestrel.rules.Article
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * BleepingComputer 보안 뉴스 목록(`/news/security/`, `/news/security/page/N/`)을 읽는다.
 * RSS는 보안 외 기사까지 섞여 있어, 섀도 재생에서 검증한 목록 페이지를 그대로 쓴다.
 * 시각은 미국 동부 시간의 분 단위("October 26, 2026" + "06:26 AM")로만 나온다.
 */
object BleepingListParser {
    const val SOURCE_CODE = "BC"
    private const val SOURCE = "BleepingComputer"
    private val EASTERN = ZoneId.of("America/New_York")
    private val STAMP = DateTimeFormatter.ofPattern("MMMM d, yyyy h:mm a", Locale.ENGLISH)
    private val ROW = Regex(
        """<h4><a href="([^"]+)"[^>]*>(.*?)</a></h4>\s*<p>(.*?)</p>.*?<li class="bc_news_date">(.*?)</li>\s*<li class="bc_news_time">(.*?)</li>""",
        RegexOption.DOT_MATCHES_ALL,
    )

    /** 기사가 한 건도 없으면 화면 구조가 바뀐 것으로 본다. */
    fun parse(html: String): Parsed<Linked<Article>> {
        val rows = ROW.findAll(html).toList()
        if (rows.isEmpty()) throw SourceFormatException(SOURCE, "기사 목록을 찾지 못함(화면 구조 변경 또는 차단)")
        return rows.map { m ->
            orSkip {
                val (url, title, summary, date, time) = m.destructured
                val article = Article(
                    source = SOURCE_CODE,
                    publishedAt = LocalDateTime.parse("$date $time", STAMP).atZone(EASTERN).toInstant(),
                    title = Html.unescape(Html.stripTags(title, "")),
                    text = Html.unescape(Html.stripTags(summary, "")),
                )
                Linked(article, url)
            }
        }.toParsed()
    }
}
