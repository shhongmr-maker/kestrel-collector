package kestrel.collector

import kestrel.rules.KisaPost
import java.time.LocalDate

/** 보호나라(KISA) 게시판 RSS(`/kr/rss.do?bbsId=…`)를 읽는다. 날짜는 "2026-10-26"처럼 날짜만 온다. */
object BohoRssParser {
    private const val SOURCE = "보호나라 RSS"
    private val SPACES = Regex("\\s+")

    fun parse(xml: String): Parsed<Linked<KisaPost>> {
        val root = Xml.parse(SOURCE, xml).documentElement
        val channel = root.takeIf { it.localName == "rss" }?.child("channel")
            ?: throw SourceFormatException(SOURCE, "rss/channel 없음")
        return channel.children("item").map { item ->
            orSkip {
                val post = KisaPost(
                    date = LocalDate.parse(item.childText("pubDate")!!.trim()),
                    // 게시판 목록을 긁던 Python 시제품과 같게 공백을 한 칸으로 모은다
                    title = item.childText("title")!!.replace(SPACES, " ").trim().also { require(it.isNotEmpty()) },
                )
                Linked(post, item.childText("link")?.trim().orEmpty())
            }
        }.toParsed()
    }
}
