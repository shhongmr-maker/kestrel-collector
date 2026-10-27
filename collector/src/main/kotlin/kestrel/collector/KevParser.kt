package kestrel.collector

import kestrel.rules.KevEntry
import org.json.JSONException
import org.json.JSONObject
import java.time.LocalDate

/** CISA KEV 카탈로그 전체. [catalogVersion]이 state에 저장한 값과 같으면 바뀐 것이 없다. */
data class KevCatalog(val catalogVersion: String, val dateReleased: String, val entries: Parsed<KevEntry>)

/** `known_exploited_vulnerabilities.json`을 읽는다. */
object KevParser {
    private const val SOURCE = "CISA KEV"

    fun parse(json: String): KevCatalog {
        val root = try {
            JSONObject(json)
        } catch (e: JSONException) {
            throw SourceFormatException(SOURCE, "JSON이 아님", e)
        }
        val arr = root.optJSONArray("vulnerabilities") ?: throw SourceFormatException(SOURCE, "vulnerabilities 배열 없음")
        val entries = (0 until arr.length()).map { i ->
            orSkip {
                val v = arr.getJSONObject(i)
                KevEntry(
                    cveId = v.getString("cveID"),
                    vendorProject = v.getString("vendorProject"),
                    product = v.getString("product"),
                    dateAdded = LocalDate.parse(v.getString("dateAdded")),
                    // 아래는 화면·조치 가이드 근거용이라 없거나 형식이 달라도 항목을 버리지 않는다
                    name = v.optString("vulnerabilityName").clip(200),
                    shortDescription = v.optString("shortDescription").clip(1000),
                    requiredAction = v.optString("requiredAction").clip(500),
                    dueDate = runCatching { LocalDate.parse(v.optString("dueDate")) }.getOrNull(),
                    ransomware = v.optString("knownRansomwareCampaignUse").clip(20),
                )
            }
        }
        return KevCatalog(root.optString("catalogVersion"), root.optString("dateReleased"), entries.toParsed())
    }
}
