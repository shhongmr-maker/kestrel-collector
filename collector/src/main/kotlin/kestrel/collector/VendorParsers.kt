package kestrel.collector

import kestrel.rules.VendorAdvisory
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.w3c.dom.Element
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/**
 * 제조사 보안 공지(v6.3). 형식은 2026-11-04에 받은 실제 응답으로 확인했다.
 * - Fortinet PSIRT RSS: 제목·요약(HTML)·게시일, 요약 끝에 "Revised on YYYY-MM-DD"
 * - Cisco Security Advisory RSS: 제목·요약(HTML)·게시일("2026-11-03 17:05:12.0")
 * - Ivanti 블로그 RSS: 분류가 "Security Advisory"인 글만(월간 보안 업데이트·긴급 공지)
 * - Palo Alto Networks: 공지 목록 JSON과 공지별 CVE 기록 JSON(exploits 문구, CVSS 위협 지표 E:A)
 * 판정에는 실제 악용 문구만 쓰고(rules-core [kestrel.rules.VendorExploit]), 요약은 화면 근거로 짧게 둔다.
 */
object VendorParsers {
    const val FORTINET = "Fortinet"
    const val CISCO = "Cisco"
    const val IVANTI = "Ivanti"
    const val PALO_ALTO = "Palo Alto Networks"
    /** 저장하는 요약 길이 */
    const val TEXT_MAX = 1500

    private val CVE = Regex("""CVE-\d{4}-\d{4,7}""")
    private val REVISED = Regex("""Revised on (\d{4}-\d{2}-\d{2})""")
    private val SPACES = Regex("[ \\t\\u00A0]+")
    private val CISCO_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss[.S]")

    private fun channel(source: String, xml: String): Element =
        Xml.parse(source, xml).documentElement.takeIf { it.localName == "rss" }?.child("channel")
            ?: throw SourceFormatException(source, "rss/channel 없음")

    private fun text(html: String): String = HtmlText.of(html).lines().joinToString("\n") { SPACES.replace(it, " ").trim() }.clip(TEXT_MAX)

    private fun cves(vararg s: String): List<String> = s.flatMap { t -> CVE.findAll(t).map { it.value } }.distinct().sorted()

    /** RSS 날짜. "Tue, 13 Oct 2026 14:33:02 Z"처럼 Z로 끝나는 것도 받는다 */
    internal fun rfc1123(s: String): Instant {
        val t = s.trim().replace(Regex(" Z$"), " GMT")
        return ZonedDateTime.parse(t, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant()
    }

    private fun day(i: Instant): LocalDate = i.atZone(ZoneOffset.UTC).toLocalDate()

    fun fortinet(xml: String): Parsed<Linked<VendorAdvisory>> = channel(FORTINET, xml).children("item").map { item ->
        orSkip {
            val link = item.childText("link")!!.trim().also { require(it.startsWith("https://fortiguard.fortinet.com/")) }
            val title = Html.unescape(item.childText("title")!!).trim().also { require(it.isNotEmpty()) }
            val desc = item.childText("description").orEmpty()
            val body = text(desc)
            val published = day(rfc1123(item.childText("pubDate")!!))
            val revised = REVISED.findAll(body).mapNotNull { runCatching { LocalDate.parse(it.groupValues[1]) }.getOrNull() }.maxOrNull()
            val date = listOfNotNull(published, revised).max()
            Linked(VendorAdvisory(FORTINET, date, title.clip(200), body, cves(title, body)), link.replace("/psirt/cvrf/", "/psirt/"))
        }
    }.toParsed()

    fun cisco(xml: String): Parsed<Linked<VendorAdvisory>> = channel(CISCO, xml).children("item").map { item ->
        orSkip {
            val link = item.childText("link")!!.trim().substringBefore('?').also { require(it.startsWith("https://sec.cloudapps.cisco.com/")) }
            val title = Html.unescape(item.childText("title")!!).trim().also { require(it.isNotEmpty()) }
            val body = text(item.childText("description").orEmpty())
            // 시간대가 적혀 있지 않다. 날짜만 쓰므로 UTC로 본다(하루 어긋날 수 있음)
            val date = LocalDateTime.parse(item.childText("pubDate")!!.trim(), CISCO_TIME).toLocalDate()
            Linked(VendorAdvisory(CISCO, date, title.clip(200), body, cves(title, body)), link)
        }
    }.toParsed()

    fun ivanti(xml: String): Parsed<Linked<VendorAdvisory>> = channel(IVANTI, xml).children("item")
        .filter { item -> item.children("category").any { it.textContent.trim().equals("Security Advisory", ignoreCase = true) } }
        .map { item ->
            orSkip {
                val link = item.childText("link")!!.trim().also { require(it.startsWith("https://www.ivanti.com/")) }
                val title = Html.unescape(item.childText("title")!!).trim().also { require(it.isNotEmpty()) }
                val body = text(item.childText("description").orEmpty())
                Linked(VendorAdvisory(IVANTI, day(rfc1123(item.childText("pubDate")!!)), title.clip(200), body, cves(title, body)), link)
            }
        }.toParsed()

    /** Palo Alto Networks 공지 목록 한 건(요약·악용 여부는 [paloAltoRecord]로 채운다) */
    data class PaloAltoItem(val id: String, val title: String, val date: LocalDate, val severity: String)

    fun paloAltoList(json: String): Parsed<PaloAltoItem> {
        val arr = try {
            JSONArray(json)
        } catch (e: JSONException) {
            throw SourceFormatException(PALO_ALTO, "JSON 배열이 아님", e)
        }
        return (0 until arr.length()).map { i ->
            orSkip {
                val o = arr.getJSONObject(i)
                val id = o.getString("ID").trim().also { require(it.matches(Regex("""(CVE-\d{4}-\d{4,7}|PAN-SA-\d{4}-\d{4})"""))) }
                val date = listOf("updated", "date").mapNotNull { k -> o.optString(k).takeIf { it.isNotEmpty() }?.let { day(Instant.parse(it)) } }.max()
                PaloAltoItem(id, o.getString("title").trim().clip(200), date, o.optString("threatSeverity", o.optString("baseSeverity", "")).uppercase())
            }
        }.toParsed()
    }

    /** 공지별 CVE 기록: exploits 문구와 CVSS 4.0 위협 지표(E:A = 실제 공격 확인) */
    fun paloAltoRecord(item: PaloAltoItem, json: String): VendorAdvisory {
        val cna = try {
            JSONObject(json).getJSONObject("containers").getJSONObject("cna")
        } catch (e: JSONException) {
            throw SourceFormatException(PALO_ALTO, "CVE 기록 형식이 다름", e)
        }
        val statement = cna.optJSONArray("exploits")?.let { a -> (0 until a.length()).mapNotNull { a.optJSONObject(it)?.optString("value") } }.orEmpty()
            .joinToString("\n").clip(600)
        val vectors = cna.optJSONArray("metrics")?.let { a -> (0 until a.length()).mapNotNull { a.optJSONObject(it)?.optJSONObject("cvssV4_0")?.optString("vectorString") } }.orEmpty()
        val attacked = vectors.any { "/E:A" in it }
        val desc = cna.optJSONArray("descriptions")?.optJSONObject(0)?.optString("value").orEmpty()
        val body = listOf(statement, desc).filter { it.isNotBlank() }.joinToString("\n").clip(TEXT_MAX)
        return VendorAdvisory(PALO_ALTO, item.date, item.title, body, cves(item.id, item.title), exploited = if (attacked) true else null)
    }

    fun paloAltoUrl(id: String) = "https://security.paloaltonetworks.com/$id"
}
