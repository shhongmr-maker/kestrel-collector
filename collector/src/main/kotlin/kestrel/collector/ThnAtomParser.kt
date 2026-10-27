package kestrel.collector

import kestrel.rules.Article
import java.time.OffsetDateTime

/**
 * The Hacker News의 Blogger Atom 피드(`/feeds/posts/default?published-min=…&published-max=…`)를 읽는다.
 * 본문은 content가 없으면 summary를 쓰고, 태그를 공백으로 바꾼 뒤 3,000자까지 둔다(fetch_news.py와 같음).
 */
object ThnAtomParser {
    const val SOURCE_CODE = "THN"
    private const val SOURCE = "The Hacker News"
    private const val ATOM = "http://www.w3.org/2005/Atom"
    private const val OPEN_SEARCH = "http://a9.com/-/spec/opensearchrss/1.0/"

    fun parse(xml: String): Page<Linked<Article>> {
        val feed = Xml.parse(SOURCE, xml).documentElement
        if (feed.localName != "feed" || feed.namespaceURI != ATOM) throw SourceFormatException(SOURCE, "Atom feed 아님")
        val entries = feed.children("entry", ATOM)
        val articles = entries.map { e ->
            orSkip {
                val body = (e.child("content", ATOM) ?: e.child("summary", ATOM))?.textContent.orEmpty()
                val article = Article(
                    source = SOURCE_CODE,
                    publishedAt = OffsetDateTime.parse(e.childText("published", ATOM)!!).toInstant(),
                    title = e.childText("title", ATOM)!!,
                    text = Html.unescape(Html.stripTags(body, " ")).takeCodePoints(3000),
                )
                val link = e.children("link", ATOM).firstOrNull { it.getAttribute("rel") == "alternate" }?.getAttribute("href")
                Linked(article, link.orEmpty())
            }
        }
        // openSearch:startIndex는 1부터 센다
        val start = feed.childText("startIndex", OPEN_SEARCH)?.trim()?.toIntOrNull() ?: 1
        val total = feed.childText("totalResults", OPEN_SEARCH)?.trim()?.toIntOrNull() ?: entries.size
        return Page(articles.filterNotNull(), articles.count { it == null }, total, start - 1 + entries.size)
    }
}
