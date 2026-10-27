package kestrel.collector

import kestrel.rules.NvdCve
import kestrel.rules.VersionRange
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.time.LocalDate

/** NVD CVE API 2.0(`/rest/json/cves/2.0`) 응답 한 페이지를 읽는다. */
object NvdParser {
    private const val SOURCE = "NVD"
    private val METRIC_KEYS = listOf("cvssMetricV40", "cvssMetricV31", "cvssMetricV30")
    private const val MAX_RANGES = 24
    private const val MAX_REFERENCES = 8
    private val LESS = Regex("""^\s*<(=)?\s*(\S+)\s*$""")

    fun parsePage(json: String): Page<NvdCve> {
        val root = try {
            JSONObject(json)
        } catch (e: JSONException) {
            throw SourceFormatException(SOURCE, "JSON이 아님", e)
        }
        val arr = root.optJSONArray("vulnerabilities") ?: throw SourceFormatException(SOURCE, "vulnerabilities 배열 없음")
        if (!root.has("totalResults")) throw SourceFormatException(SOURCE, "totalResults 없음")
        val cves = (0 until arr.length()).map { i -> orSkip { parseCve(arr.getJSONObject(i).getJSONObject("cve")) } }
        return Page(
            items = cves.filterNotNull(),
            skipped = cves.count { it == null },
            total = root.getInt("totalResults"),
            nextOffset = root.optInt("startIndex") + root.optInt("resultsPerPage", arr.length()),
        )
    }

    /**
     * `vulnerabilities[].cve` 객체 하나. 설명은 영어 설명(없으면 첫 설명),
     * CVSS는 v4.0 → v3.1 → v3.0 순서로 처음 있는 지표의 첫 항목을 쓴다(research/shadow/engine.py와 같음).
     * 영향 범위와 참고 링크는 화면 근거용이라, 형식이 달라도 CVE를 버리지 않고 빈 목록으로 둔다.
     */
    fun parseCve(c: JSONObject): NvdCve {
        val descriptions = c.getJSONArray("descriptions")
        val description = (0 until descriptions.length()).map { descriptions.getJSONObject(it) }
            .let { all -> all.firstOrNull { it.optString("lang") == "en" } ?: all.first() }
            .getString("value")
        val metrics = c.optJSONObject("metrics") ?: JSONObject()
        val cvss = METRIC_KEYS.firstNotNullOfOrNull { key ->
            metrics.optJSONArray(key)?.takeIf { it.length() > 0 }?.getJSONObject(0)?.getJSONObject("cvssData")
        }
        return NvdCve(
            id = c.getString("id"),
            // NVD 시각은 오프셋 없는 UTC("2026-05-12T18:16:35.687")다
            published = LocalDate.parse(c.getString("published").substring(0, 10)),
            description = description,
            cvssScore = cvss?.getDouble("baseScore"),
            cvssVector = cvss?.getString("vectorString"),
            affected = runCatching { (fromConfigurations(c) + fromAffected(c)).distinct().take(MAX_RANGES) }.getOrDefault(emptyList()),
            references = runCatching { references(c) }.getOrDefault(emptyList()),
        )
    }

    /** NVD 분석 결과(`configurations[].nodes[].cpeMatch[]`)의 취약 조건. */
    internal fun fromConfigurations(c: JSONObject): List<VersionRange> {
        val out = mutableListOf<VersionRange>()
        for (conf in c.optJSONArray("configurations").objects()) {
            for (node in conf.optJSONArray("nodes").objects()) {
                for (m in node.optJSONArray("cpeMatch").objects()) {
                    if (!m.optBoolean("vulnerable")) continue
                    val parts = m.optString("criteria").split(':')
                    if (parts.size < 6) continue
                    val version = parts[5].takeUnless { it == "*" || it == "-" || it.isEmpty() }
                    val startIn = m.opt("versionStartIncluding") as? String
                    val startEx = m.opt("versionStartExcluding") as? String
                    out += VersionRange(
                        vendor = parts[3].clip(80), product = parts[4].clip(80),
                        exact = version?.clip(40),
                        from = (startIn ?: startEx)?.clip(40), fromExcluding = startIn == null && startEx != null,
                        lessThan = (m.opt("versionEndExcluding") as? String)?.clip(40),
                        lessThanOrEqual = (m.opt("versionEndIncluding") as? String)?.clip(40),
                    )
                }
            }
        }
        return out
    }

    /** CNA가 낸 영향 범위(`affected[].affectedData[].versions[]`). "0"은 처음부터라는 뜻이고, "< 9.3.7" 같은 표기도 받는다. */
    internal fun fromAffected(c: JSONObject): List<VersionRange> {
        val out = mutableListOf<VersionRange>()
        for (a in c.optJSONArray("affected").objects()) {
            for (d in a.optJSONArray("affectedData").objects()) {
                val vendor = d.optString("vendor").clip(80)
                val product = d.optString("product").clip(80)
                for (v in d.optJSONArray("versions").objects()) {
                    if (v.optString("status") != "affected") continue
                    val version = v.optString("version").trim()
                    val lt = (v.opt("lessThan") as? String)?.clip(40)
                    val le = (v.opt("lessThanOrEqual") as? String)?.clip(40)
                    val less = LESS.find(version)
                    out += when {
                        less != null && less.groupValues[1].isEmpty() -> VersionRange(vendor, product, lessThan = less.groupValues[2].clip(40))
                        less != null -> VersionRange(vendor, product, lessThanOrEqual = less.groupValues[2].clip(40))
                        lt != null || le != null -> VersionRange(vendor, product, from = version.takeUnless { it == "0" || it.isEmpty() || it == "*" }?.clip(40), lessThan = lt, lessThanOrEqual = le)
                        version.isNotEmpty() && version != "*" -> VersionRange(vendor, product, exact = version.clip(40))
                        else -> continue
                    }
                }
            }
        }
        return out
    }

    /** 참고 링크. https만 남기고, 벤더 권고·패치 표시가 붙은 링크를 앞에 둔다. */
    internal fun references(c: JSONObject): List<String> {
        val refs = c.optJSONArray("references").objects().mapNotNull { r ->
            val url = r.optString("url").trim()
            if (!url.startsWith("https://") || url.length > 500) return@mapNotNull null
            val tags = r.optJSONArray("tags")?.let { t -> (0 until t.length()).map { t.optString(it) } }.orEmpty()
            url to (if ("Vendor Advisory" in tags || "Patch" in tags) 0 else 1)
        }
        return refs.sortedBy { it.second }.map { it.first }.distinct().take(MAX_REFERENCES)
    }

    private fun JSONArray?.objects(): List<JSONObject> = if (this == null) emptyList() else (0 until length()).mapNotNull { optJSONObject(it) }
}
