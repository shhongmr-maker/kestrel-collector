package kestrel.collector

import kestrel.rules.Article
import kestrel.rules.CvssRule
import kestrel.rules.KevEntry
import kestrel.rules.KisaPost
import kestrel.rules.NvdCve
import kestrel.rules.ProductCatalog
import kestrel.rules.SignalKind
import java.net.URLEncoder
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** 소스 한 번 조회 결과. [notModified]면 캐시를 그대로 쓴다. */
data class Poll<T>(
    val items: List<Linked<T>>,
    val cursor: String?,
    val notModified: Boolean = false,
    val skipped: Int = 0,
    val warning: String? = null,
)

/**
 * 소스별 요청 방법. 이어 받기 위치(cursor)가 없으면 [since]부터 받는다.
 * 요청 사이 대기는 [sleep]으로 하므로 테스트에서는 기다리지 않는다.
 */
class Sources(
    private val fetcher: Fetcher,
    private val nvdApiKey: String? = null,
    private val sleep: (Duration) -> Unit = { Thread.sleep(it.toMillis()) },
) {
    companion object {
        const val KEV = "kev"
        const val NVD = "nvd"
        const val KISA = "kisa"
        const val THN = "thn"
        const val BC = "bc"
        const val DS = "ds"
        val ALL = listOf(KEV, NVD, KISA, THN, BC, DS)

        const val KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        const val NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        const val KISA_URL = "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133"
        const val THN_URL = "https://thehackernews.com/feeds/posts/default"
        const val BC_URL = "https://www.bleepingcomputer.com/news/security/"
        const val DS_URL = "https://www.dailysecu.com/rss/allArticle.xml"

        /** NVD는 증분 동기화를 2시간에 한 번 이하로 하라고 권고한다(검증 필요 목록 참고). */
        val NVD_INTERVAL: Duration = Duration.ofHours(2)
        /** 이어 받을 때 앞쪽으로 겹쳐 받는 시간. 출처 시각 오차와 늦게 색인되는 글을 놓치지 않으려고 둔다. */
        val OVERLAP: Duration = Duration.ofHours(1)
        const val BC_MAX_PAGES = 10
        const val KISA_BODY_MAX = 4000
        /** 한 실행에서 받는 보호나라 본문 수. 공지가 몰려도 요청이 늘지 않게 한다(못 받은 것은 다음 실행). */
        const val KISA_BODIES_PER_RUN = 3

        private val NVD_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS").withZone(ZoneOffset.UTC)
        private val ISO_SECONDS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)
    }

    private fun ok(source: String, url: String, headers: Map<String, String> = emptyMap()): HttpResult {
        val res = try {
            fetcher.get(url, headers)
        } catch (e: java.io.IOException) {
            throw SourceFetchException(source, "연결 실패: ${e.message}", e)
        }
        if (res.status != 200 && res.status != 304) throw SourceFetchException(source, "HTTP ${res.status}")
        return res
    }

    /** CISA KEV. If-Modified-Since로 바뀌지 않았으면 304를 받는다(2026-10-26 확인). */
    fun kev(cursor: String?): Poll<KevEntry> {
        val res = ok(KEV, KEV_URL, cursor?.let { mapOf("If-Modified-Since" to it) } ?: emptyMap())
        if (res.status == 304) return Poll(emptyList(), cursor, notModified = true)
        val catalog = KevParser.parse(res.body)
        return Poll(
            items = catalog.entries.items.map { Linked(it, "https://nvd.nist.gov/vuln/detail/${it.cveId}") },
            cursor = res.header("last-modified"),
            skipped = catalog.entries.skipped,
        )
    }

    /**
     * NVD. 핵심 제품군 설명에 걸리는 CVE와, 제품군 밖이라도 S1(CVSS 9 이상·원격·무인증·무상호작용)인 CVE만 남긴다(v6).
     * 첫 실행([cursor]가 null)은 [since] 이후 **공개된** CVE를, 그다음부터는 마지막으로 받은 뒤 **수정된** CVE를 받는다.
     * 수정 시각 기준으로 처음부터 받으면 오래된 CVE의 수정분까지 와서 첫 실행이 매우 길어진다.
     * 섀도 재생은 제품군별 키워드 검색이었지만, 실시간에서는 요청 수를 줄이려고 한 번에 받는다.
     */
    fun nvd(cursor: Instant?, since: Instant, now: Instant): Poll<NvdCve> {
        val start = maxOf((cursor ?: since).minus(if (cursor != null) OVERLAP else Duration.ZERO), now.minus(Duration.ofDays(119)))
        val range = if (cursor == null) "pubStartDate=${NVD_TIME.format(start)}&pubEndDate=${NVD_TIME.format(now)}"
        else "lastModStartDate=${NVD_TIME.format(start)}&lastModEndDate=${NVD_TIME.format(now)}"
        val pause = if (nvdApiKey != null) Duration.ofMillis(700) else Duration.ofMillis(6500)
        val headers = nvdApiKey?.let { mapOf("apiKey" to it) } ?: emptyMap()
        val out = mutableListOf<Linked<NvdCve>>()
        var skipped = 0
        var offset = 0
        while (true) {
            if (offset > 0) sleep(pause)
            val url = "$NVD_URL?$range&resultsPerPage=2000&startIndex=$offset"
            val page = NvdParser.parsePage(ok(NVD, url, headers).body)
            out += page.items
                .filter { c -> c.published >= since.atZone(ZoneOffset.UTC).toLocalDate() }
                .filter { c -> keepNvd(c) }
                .map { Linked(it, "https://nvd.nist.gov/vuln/detail/${it.id}") }
            skipped += page.skipped
            if (!page.hasMore || page.nextOffset <= offset) break
            offset = page.nextOffset
        }
        // 형식이 어긋난 CVE가 있었으면 이어 받기 위치를 옮기지 않아 다음 실행이 같은 구간을 다시 받게 한다
        return Poll(out, if (skipped > 0) cursor?.toString() else now.toString(), skipped = skipped)
    }

    private fun keepNvd(c: NvdCve): Boolean {
        if (ProductCatalog.groups.any { it.textPattern.containsMatchIn(c.description) }) return true
        val score = c.cvssScore ?: return false
        val vector = c.cvssVector ?: return false
        return CvssRule.classify(score, vector) == SignalKind.S1
    }

    /** 데일리시큐 RSS(최근 50건). 캐시의 마지막 글보다 오래된 글이 없으면 사이에 빠진 글이 있을 수 있다. */
    fun ds(cached: List<Article>, now: Instant): Poll<Article> {
        val parsed = DailySecuRssParser.parse(ok(DS, DS_URL).body)
        val newestCached = cached.filter { it.source == DailySecuRssParser.SOURCE_CODE }.maxOfOrNull { it.publishedAt }
        val oldestFetched = parsed.items.minOfOrNull { it.value.publishedAt }
        val gap = newestCached != null && oldestFetched != null && oldestFetched > newestCached
        return Poll(
            parsed.items, now.toString(), skipped = parsed.skipped,
            warning = if (gap) "RSS 범위 밖으로 빠진 기사가 있을 수 있음 ($newestCached ~ $oldestFetched)" else null,
        )
    }

    /** 보호나라 보안공지 RSS. 최근 10여 건만 오므로, 캐시의 마지막 글보다 오래된 글이 없으면 사이에 빠진 글이 있을 수 있다. */
    fun kisa(cached: List<KisaPost>, now: Instant): Poll<KisaPost> {
        val parsed = BohoRssParser.parse(ok(KISA, KISA_URL).body)
        val newestCached = cached.maxOfOrNull { it.date }
        val oldestFetched = parsed.items.minOfOrNull { it.value.date }
        val gap = newestCached != null && oldestFetched != null && oldestFetched > newestCached
        return Poll(
            parsed.items, now.toString(), skipped = parsed.skipped,
            warning = if (gap) "RSS 범위 밖으로 빠진 공지가 있을 수 있음 ($newestCached ~ $oldestFetched)" else null,
        )
    }

    /**
     * 보호나라 공지 본문(일반 텍스트, 최대 [KISA_BODY_MAX]자). 화면과 조치 가이드의 근거로만 쓴다.
     * 보호나라 주소만 받는다. 본문 영역(`content_html`)을 못 찾으면 형식이 바뀐 것으로 보고 예외.
     */
    fun kisaBody(url: String): String {
        require(url.startsWith("https://www.boho.or.kr/")) { "보호나라 주소가 아님" }
        val html = ok(KISA, url).body
        val start = html.indexOf("class=\"content_html\"")
        if (start < 0) throw SourceFormatException(KISA, "공지 본문 영역 없음")
        val bodyStart = html.indexOf('>', start) + 1
        val end = html.indexOf("<script", bodyStart).takeIf { it > 0 } ?: html.length
        return HtmlText.of(html.substring(bodyStart, end)).clip(KISA_BODY_MAX)
    }

    /** The Hacker News. Blogger 피드를 게시 시각 범위로 페이지를 넘기며 받는다. */
    fun thn(since: Instant, now: Instant): Poll<Article> {
        val out = mutableListOf<Linked<Article>>()
        var skipped = 0
        var startIndex = 1
        while (true) {
            if (startIndex > 1) sleep(Duration.ofSeconds(1))
            val url = "$THN_URL?published-min=${enc(ISO_SECONDS.format(since.minus(OVERLAP)))}" +
                "&published-max=${enc(ISO_SECONDS.format(now.plus(OVERLAP)))}&max-results=150&start-index=$startIndex"
            val page = ThnAtomParser.parse(ok(THN, url).body)
            out += page.items
            skipped += page.skipped
            if (!page.hasMore || page.nextOffset + 1 <= startIndex) break
            startIndex = page.nextOffset + 1
        }
        return Poll(out, now.toString(), skipped = skipped)
    }

    /** BleepingComputer 보안 뉴스 목록. 페이지의 가장 오래된 글이 [since]보다 앞설 때까지(최대 10쪽) 넘긴다. */
    fun bc(since: Instant, now: Instant): Poll<Article> {
        val out = mutableListOf<Linked<Article>>()
        var skipped = 0
        for (p in 1..BC_MAX_PAGES) {
            if (p > 1) sleep(Duration.ofMillis(1500))
            val parsed = try {
                BleepingListParser.parse(ok(BC, if (p == 1) BC_URL else "${BC_URL}page/$p/").body)
            } catch (e: Exception) {
                // 2쪽 이후가 실패하면 받은 데까지 쓰고, 이어 받기 위치는 옮기지 않아 다음 실행이 빈 구간을 다시 받게 한다
                if (p == 1 || (e !is SourceFetchException && e !is SourceFormatException)) throw e
                return Poll(out, since.toString(), skipped = skipped, warning = "${p}쪽 받기 실패: ${e.message}")
            }
            out += parsed.items
            skipped += parsed.skipped
            val oldest = parsed.items.minOfOrNull { it.value.publishedAt } ?: break
            if (oldest < since.minus(OVERLAP)) break
            if (p == BC_MAX_PAGES) {
                return Poll(out, now.toString(), skipped = skipped, warning = "${BC_MAX_PAGES}쪽까지 받았지만 마지막 수집 시각에 닿지 못함")
            }
        }
        return Poll(out, now.toString(), skipped = skipped)
    }

    private fun enc(s: String) = URLEncoder.encode(s, Charsets.UTF_8)
}
