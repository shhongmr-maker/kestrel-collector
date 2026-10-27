package kestrel.collector

import kestrel.rules.Article
import kestrel.rules.KevEntry
import kestrel.rules.KisaPost
import kestrel.rules.Level
import kestrel.rules.NvdCve
import kestrel.rules.Signal
import kestrel.rules.SignalKind
import kestrel.rules.VersionRange
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONStringer
import java.time.Instant
import java.time.LocalDate

/**
 * state.json과 feed.json 읽기·쓰기. 키 순서를 고정해서 쓰므로 같은 상태는 항상 같은 파일이 된다(커밋 차이 최소화).
 */
object Json {
    const val STATE_VERSION = 1

    /**
     * 화면용 필드(영향 범위·참고 링크 등) 판. 이보다 낮은 state를 읽으면 NVD 이어 받기 위치를 지워
     * 다음 실행이 30일치를 다시 받게 한다(캐시의 예전 CVE에도 영향 범위가 채워지도록).
     */
    const val DETAIL_VERSION = 1

    // ---- 쓰기 ----

    private class W {
        val s = JSONStringer()
        fun obj(block: W.() -> Unit) { s.`object`(); block(); s.endObject() }
        fun arr(block: W.() -> Unit) { s.array(); block(); s.endArray() }
        fun key(k: String): W { s.key(k); return this }
        fun v(value: Any?) { s.value(value ?: JSONObject.NULL) }
        fun f(k: String, value: Any?) { key(k); v(value?.toString()?.takeIf { value !is Number && value !is Boolean } ?: value) }
        fun fa(k: String, block: W.() -> Unit) { key(k); arr(block) }
        fun fo(k: String, block: W.() -> Unit) { key(k); obj(block) }
    }

    private fun <T> W.seen(list: List<Seen<T>>, body: W.(T) -> Unit) = arr {
        for (x in list) obj { body(x.value); f("url", x.url); f("firstSeen", x.firstSeen) }
    }

    fun writeState(st: CollectorState): String = W().apply {
        obj {
            f("version", STATE_VERSION)
            f("detailVersion", DETAIL_VERSION)
            f("initialized", st.initialized)
            f("rulesVersion", st.rulesVersion)
            fo("sources") {
                for ((name, s) in st.sources.toSortedMap()) fo(name) {
                    f("lastAttemptAt", s.lastAttemptAt); f("lastSuccessAt", s.lastSuccessAt)
                    f("error", s.error); f("warning", s.warning); f("cursor", s.cursor)
                }
            }
            key("kev").seen(st.kev) {
                f("cveId", it.cveId); f("vendorProject", it.vendorProject); f("product", it.product); f("dateAdded", it.dateAdded)
                f("name", it.name); f("shortDescription", it.shortDescription); f("requiredAction", it.requiredAction)
                f("dueDate", it.dueDate); f("ransomware", it.ransomware)
            }
            key("nvd").seen(st.nvd) {
                f("id", it.id); f("published", it.published); f("description", it.description)
                f("cvssScore", it.cvssScore); f("cvssVector", it.cvssVector)
                fa("affected") { for (r in it.affected) range(r) }
                fa("references") { it.references.forEach { u -> v(u) } }
            }
            key("kisa").seen(st.kisa) { f("date", it.date); f("title", it.title); f("body", it.body) }
            key("news").seen(st.news) { f("source", it.source); f("publishedAt", it.publishedAt); f("title", it.title); f("text", it.text) }
            fa("notified") {
                for (n in st.notified) obj {
                    f("date", n.date); f("clusterKey", n.clusterKey); f("level", n.level); f("trigger", n.trigger); f("firstSeen", n.firstSeen)
                }
            }
            fo("bodyFailures") { for ((url, n) in st.bodyFailures.toSortedMap()) f(url, n) }
            fo("followups") { for ((key, at) in st.followups.toSortedMap()) f(key, at) }
        }
    }.s.toString()

    private fun W.range(r: VersionRange) = obj {
        f("vendor", r.vendor); f("product", r.product); f("exact", r.exact); f("from", r.from); f("fromExcluding", r.fromExcluding)
        f("lessThan", r.lessThan); f("lessThanOrEqual", r.lessThanOrEqual)
    }

    private fun W.doc(d: SourceDoc) = obj {
        f("id", d.id); f("kind", d.kind); f("title", d.title); f("url", d.url); f("date", d.date); f("text", d.text)
    }

    fun writeFeed(feed: Feed): String = W().apply {
        obj {
            f("schema", Feed.SCHEMA)
            f("generatedAt", feed.generatedAt)
            fa("sources") {
                for (s in feed.sources) obj {
                    f("name", s.name); f("ok", s.ok); f("lastSuccessAt", s.lastSuccessAt); f("lastAttemptAt", s.lastAttemptAt)
                    f("error", s.error); f("warning", s.warning)
                }
            }
            fa("events") { for (e in feed.events) event(e) }
            feed.appAdvisory?.let { a -> fo("appAdvisory") { f("minVersionCode", a.minVersionCode); f("message", a.message); f("url", a.url) } }
            fo("clusters") {
                for ((k, c) in feed.clusters.toSortedMap()) fo(k) {
                    f("category", c.category); f("product", c.product)
                    fa("cves") { c.cves.forEach { v(it) } }
                    key("cvss"); c.cvss?.let { x -> obj { f("cve", x.cve); f("score", x.score); f("vector", x.vector) } } ?: v(null)
                    fa("kev") {
                        for (x in c.kev) obj {
                            f("cve", x.cve); f("name", x.name); f("dateAdded", x.dateAdded); f("dueDate", x.dueDate)
                            f("requiredAction", x.requiredAction); f("ransomware", x.ransomware)
                        }
                    }
                    fa("ranges") { for (r in c.ranges) obj { f("cve", r.cve); key("range"); range(r.range) } }
                    fa("docs") { c.docs.forEach { doc(it) } }
                }
            }
            fa("incidents") {
                for (i in feed.incidents) obj {
                    f("key", i.key); f("title", i.title); f("level", i.level); f("firstReported", i.firstReported)
                    fa("articles") { i.articles.forEach { doc(it) } }
                }
            }
            fa("notices") { for (n in feed.notices) obj { f("date", n.date); f("title", n.title); f("url", n.url) } }
            fa("briefs") {
                for (b in feed.briefs) obj {
                    f("at", b.at); f("kind", b.kind); f("source", b.source); f("title", b.title); f("url", b.url); f("group", b.group)
                    fa("cves") { b.cves.forEach { v(it) } }
                }
            }
        }
    }.s.toString()

    fun writeEvents(events: List<FeedEvent>): String = W().apply { arr { for (e in events) event(e) } }.s.toString()

    private fun W.event(e: FeedEvent) = obj {
        f("id", e.id); f("date", e.date); f("clusterKey", e.clusterKey); f("level", e.level)
        fa("signals") { e.signals.forEach { v(it) } }
        f("trigger", e.trigger)
        f("firstSeen", e.firstSeen)
        fa("evidence") { for (s in e.evidence) obj { f("date", s.date); f("kind", s.kind.code); f("detail", s.detail) } }
        f("title", e.title)
        f("headline", e.headline)
        if (e.ref.isNotEmpty()) f("ref", e.ref)
    }

    // ---- 읽기 ----

    /** [writeEvents]로 쓴 새 알림 목록을 읽는다(push 명령). */
    fun readEvents(text: String): List<FeedEvent> = JSONArray(text).objects().map { o ->
        FeedEvent(
            id = o.getString("id"), date = o.date("date"), clusterKey = o.getString("clusterKey"), level = Level.valueOf(o.getString("level")),
            signals = o.getJSONArray("signals").let { a -> (0 until a.length()).map { a.getString(it) } },
            trigger = o.optString("trigger", ""), firstSeen = Instant.parse(o.getString("firstSeen")),
            evidence = o.getJSONArray("evidence").objects().map { Signal(it.date("date"), o.getString("clusterKey"), SignalKind.fromCode(it.getString("kind")), it.getString("detail")) },
            title = o.optString("title", ""), headline = o.optString("headline", ""), ref = o.optString("ref", ""),
        )
    }

    /** push-status.json 읽기(requeue). 토큰 끝자리 표시("…abc123")는 그대로 둔다. */
    fun readPushStatus(text: String): Pair<List<FcmSender.Result>, String?> {
        val o = JSONObject(text)
        val results = o.optJSONArray("results")?.objects()?.map {
            FcmSender.Result(it.getString("token").removePrefix("…"), it.getString("event"), it.getBoolean("ok"), it.optString("detail"))
        } ?: emptyList()
        return results to o.str("error")
    }

    fun writePushStatus(at: Instant, results: List<FcmSender.Result>, error: String?): String = W().apply {
        obj {
            f("at", at)
            f("error", error)
            f("sent", results.count { it.ok })
            f("failed", results.count { !it.ok })
            fa("results") { for (r in results) obj { f("token", "…" + r.tokenSuffix); f("event", r.eventId); f("ok", r.ok); f("detail", r.detail) } }
        }
    }.s.toString()

    private fun JSONObject.str(k: String): String? = if (isNull(k)) null else getString(k)
    private fun JSONObject.instant(k: String): Instant? = str(k)?.let(Instant::parse)
    private fun JSONObject.date(k: String): LocalDate = LocalDate.parse(getString(k))
    private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }
    private fun <T> JSONObject.seen(k: String, read: (JSONObject) -> T): List<Seen<T>> =
        optJSONArray(k)?.objects()?.map { Seen(read(it), it.getString("url"), Instant.parse(it.getString("firstSeen"))) } ?: emptyList()

    fun readState(text: String): CollectorState {
        val o = JSONObject(text)
        require(o.optInt("version") == STATE_VERSION) { "state 버전이 다름: ${o.opt("version")}" }
        val refill = o.optInt("detailVersion", 0) < DETAIL_VERSION
        val sources = o.optJSONObject("sources")?.let { src ->
            src.keySet().sorted().associateWith { name ->
                val s = src.getJSONObject(name)
                val st = SourceState(s.instant("lastAttemptAt"), s.instant("lastSuccessAt"), s.str("error"), s.str("warning"), s.str("cursor"))
                if (refill && name == Sources.NVD) st.copy(lastSuccessAt = null, cursor = null) else st
            }
        } ?: emptyMap()
        return CollectorState(
            initialized = o.optBoolean("initialized"),
            rulesVersion = o.optString("rulesVersion", ""),
            sources = sources,
            // 0.3.x가 쓴 state에는 화면용 필드가 없다. 없으면 빈 값으로 읽는다
            kev = o.seen("kev") {
                KevEntry(
                    it.getString("cveId"), it.getString("vendorProject"), it.getString("product"), it.date("dateAdded"),
                    name = it.optString("name", ""), shortDescription = it.optString("shortDescription", ""),
                    requiredAction = it.optString("requiredAction", ""),
                    dueDate = it.optStr("dueDate")?.let(LocalDate::parse), ransomware = it.optString("ransomware", ""),
                )
            },
            nvd = o.seen("nvd") {
                NvdCve(it.getString("id"), it.date("published"), it.getString("description"),
                    if (it.isNull("cvssScore")) null else it.getDouble("cvssScore"), it.str("cvssVector"),
                    affected = it.optJSONArray("affected")?.objects()?.map { r -> readRange(r) } ?: emptyList(),
                    references = it.optJSONArray("references")?.let { a -> (0 until a.length()).map { i -> a.getString(i) } } ?: emptyList(),
                )
            },
            kisa = o.seen("kisa") { KisaPost(it.date("date"), it.getString("title"), it.optString("body", "")) },
            news = o.seen("news") { Article(it.getString("source"), Instant.parse(it.getString("publishedAt")), it.getString("title"), it.getString("text")) },
            notified = o.optJSONArray("notified")?.objects()?.map {
                Notified(
                    it.date("date"), it.getString("clusterKey"), Level.valueOf(it.getString("level")),
                    Instant.parse(it.getString("firstSeen")), it.optString("trigger", ""),
                )
            } ?: emptyList(),
            bodyFailures = o.optJSONObject("bodyFailures")?.let { b -> b.keySet().sorted().associateWith { b.getInt(it) } } ?: emptyMap(),
            followups = o.optJSONObject("followups")?.let { b -> b.keySet().sorted().associateWith { Instant.parse(b.getString(it)) } } ?: emptyMap(),
        )
    }

    private fun JSONObject.optStr(k: String): String? = if (!has(k) || isNull(k)) null else getString(k)

    private fun readRange(r: JSONObject) = VersionRange(
        r.getString("vendor"), r.getString("product"), r.optStr("exact"), r.optStr("from"), r.optBoolean("fromExcluding"),
        r.optStr("lessThan"), r.optStr("lessThanOrEqual"),
    )
}
