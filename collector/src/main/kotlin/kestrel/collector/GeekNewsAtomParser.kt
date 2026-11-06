package kestrel.collector

import kestrel.rules.Article
import java.time.OffsetDateTime

/**
 * GeekNews(news.hada.io) Atom 피드(`/rss/news`, feedburner로 넘어감, 최근 20건, 2026-11-06 확인)를 읽는다.
 * 개발·기술 뉴스 큐레이션이라 뉴스 탭(보안·AI 소식)에만 쓰고 알림 판정에는 넣지 않는다.
 * 링크는 entry id의 GeekNews 글 주소(추적 꼬리표 없음)를 쓰고, 본문은 요약을 600자까지 둔다(공개 수집 결과에는 싣지 않음).
 */
object GeekNewsAtomParser {
    const val SOURCE_CODE = "GN"
    private const val SOURCE = "GeekNews"
    private const val ATOM = "http://www.w3.org/2005/Atom"
    private const val LINK_PREFIX = "https://news.hada.io/topic?id="
    private val SPACES = Regex("\\s+")

    fun parse(xml: String): Parsed<Linked<Article>> {
        val feed = Xml.parse(SOURCE, xml).documentElement
        if (feed.localName != "feed" || feed.namespaceURI != ATOM) throw SourceFormatException(SOURCE, "Atom feed 아님")
        return feed.children("entry", ATOM).map { e ->
            orSkip {
                val id = e.childText("id", ATOM)!!.trim()
                require(id.startsWith(LINK_PREFIX) && id.removePrefix(LINK_PREFIX).all { it.isDigit() })
                val body = e.childText("content", ATOM).orEmpty()
                val article = Article(
                    source = SOURCE_CODE,
                    publishedAt = OffsetDateTime.parse((e.childText("published", ATOM) ?: e.childText("updated", ATOM))!!.trim()).toInstant(),
                    title = Html.unescape(e.childText("title", ATOM)!!).replace(SPACES, " ").trim().also { require(it.isNotEmpty()) },
                    text = Html.unescape(Html.stripTags(body, " ")).replace(SPACES, " ").trim().takeCodePoints(600),
                )
                Linked(article, id)
            }
        }.toParsed()
    }
}
