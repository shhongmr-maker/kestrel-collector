package kestrel.collector

import kestrel.rules.Article
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * 데일리시큐 전체 기사 RSS(`/rss/allArticle.xml`)를 읽는다. 최근 50건만 온다(2026-10-27 확인).
 * pubDate는 "2026-10-27 00:33:18"처럼 시간대 없이 한국 시각으로 온다. 본문은 요약(description)을 600자까지 둔다.
 * 링크는 데일리시큐 주소만 받는다(앱이 원문 링크로 연다).
 */
object DailySecuRssParser {
    const val SOURCE_CODE = "DS"
    private const val SOURCE = "데일리시큐 RSS"
    private val KST = ZoneId.of("Asia/Seoul")
    private val TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    private val SPACES = Regex("\\s+")
    private const val LINK_PREFIX = "https://www.dailysecu.com/"

    fun parse(xml: String): Parsed<Linked<Article>> {
        val root = Xml.parse(SOURCE, xml).documentElement
        val channel = root.takeIf { it.localName == "rss" }?.child("channel")
            ?: throw SourceFormatException(SOURCE, "rss/channel 없음")
        return channel.children("item").map { item ->
            orSkip {
                val link = item.childText("link")!!.trim()
                require(link.startsWith(LINK_PREFIX))
                val article = Article(
                    source = SOURCE_CODE,
                    publishedAt = LocalDateTime.parse(item.childText("pubDate")!!.trim(), TIME).atZone(KST).toInstant(),
                    title = Html.unescape(item.childText("title")!!).replace(SPACES, " ").trim().also { require(it.isNotEmpty()) },
                    text = Html.unescape(Html.stripTags(item.childText("description").orEmpty(), " ")).replace(SPACES, " ").trim().takeCodePoints(600),
                )
                Linked(article, link)
            }
        }.toParsed()
    }
}
