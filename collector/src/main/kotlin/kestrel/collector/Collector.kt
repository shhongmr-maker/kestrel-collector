package kestrel.collector

import kestrel.rules.AlertEngine
import kestrel.rules.AlertEvent
import kestrel.rules.Level
import kestrel.rules.ProductCatalog
import kestrel.rules.Rules
import kestrel.rules.Signal
import kestrel.rules.SignalExtractor
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit

/** 한 번 실행한 결과. [newAlerts]가 이번에 새로 알릴 이벤트다(푸시 대상). */
data class RunResult(val state: CollectorState, val feed: Feed, val newAlerts: List<FeedEvent>)

/**
 * 수집 한 번: 소스 조회 → 캐시 병합·정리 → 신호 → 판정 → 알린 것과 비교 → feed.
 *
 * 판정은 매번 캐시 전체([windowDays]일)로 다시 하고, 이미 알린 이벤트와의 차이만 새 알림으로 낸다.
 * 그래서 실행이 빠지거나 늦어도 다음 실행이 따라잡는다. 소스 하나가 실패해도 나머지는 계속한다.
 */
class Collector(
    private val sources: Sources,
    private val windowDays: Long = 30,
    /** 이 기간 안의 이벤트만 판정 결과로 낸다. 그 앞의 [windowDays] 나머지는 클러스터 이력을 잇는 데만 쓴다. */
    private val alertDays: Long = 14,
    /** feed에 싣는 기간. */
    private val feedDays: Long = 7,
) {
    companion object {
        /** 보호나라 본문을 이만큼 실패하면 그 공지는 더 받지 않는다(형식이 바뀐 페이지를 매번 다시 요청하지 않게). */
        const val KISA_BODY_TRIES = 3
        /** 같은 취약점의 추가 보도 알림은 이 간격에 한 번까지 보낸다 */
        val FOLLOWUP_GAP: Duration = Duration.ofHours(6)
        /** 이보다 오래된 기사는 추가 보도로 알리지 않는다(소스가 되살아나 옛 기사가 한꺼번에 들어올 때) */
        val FOLLOWUP_MAX_AGE: Duration = Duration.ofHours(48)
        /** 한 실행에서 보내는 추가 보도 알림 수 상한 */
        const val MAX_FOLLOWUPS = 5
        /** 이 기간 안에 같은 위협을 알렸으면 새 알림을 상향·추가 확인·후속 보도로 보낸다([FeedEvent.relation]) */
        val RELATED_WINDOW: Duration = Duration.ofDays(7)
        private val CVE = Regex("CVE-\\d{4}-\\d{4,}")

        /** 이벤트의 근거·클러스터 키·재알림 CVE에 나온 CVE(정렬, 중복 없음) */
        fun cvesOf(e: AlertEvent, evidence: List<Signal>): List<String> =
            (listOf(e.clusterKey, e.trigger) + evidence.map { it.detail }).flatMap { t -> CVE.findAll(t).map { it.value } }.distinct().sorted()

        /**
         * 먼저 알린 같은 위협: [before] 전 [RELATED_WINDOW] 안에 알린 것 중 같은 클러스터이거나 CVE가 겹치는 것.
         * 이벤트 날짜도 [RELATED_WINDOW] 안이어야 한다(규칙 판이 바뀐 실행은 옛 이벤트를 지금 시각으로 기록하므로 기록 시각만으로는 부족하다).
         * 여럿이면 등급이 높고 늦은 것. 이벤트 자신의 기록은 뺀다
         */
        fun priorOf(e: AlertEvent, cves: List<String>, before: Instant, notified: List<Notified>): Notified? =
            notified.filter { n ->
                n.firstSeen < before && Duration.between(n.firstSeen, before) <= RELATED_WINDOW && !n.sameAs(e) &&
                    ChronoUnit.DAYS.between(n.date, e.date) in 0..RELATED_WINDOW.toDays() &&
                    (n.clusterKey == e.clusterKey || n.cves.any { it in cves })
            }.maxWithOrNull(compareBy<Notified>({ it.level }, { it.firstSeen }))

        /** 먼저 알린 위협([prior])과의 관계. 침해사고는 후속 보도, 🔴는 상향(🟠 뒤)·추가 확인(🔴 뒤), 🟠는 원래 무음이라 그대로 */
        fun relationOf(e: AlertEvent, prior: Notified?): String = when {
            prior == null -> ""
            e.clusterKey.startsWith("INC:") -> FeedEvent.UPDATE
            e.level == Level.RED -> if (prior.level == Level.RED) FeedEvent.REPEAT else FeedEvent.UPGRADE
            else -> ""
        }

        fun idOf(n: Notified) = listOf(n.date, n.clusterKey, n.level, n.trigger).filter { it.toString().isNotEmpty() }.joinToString("|")

        /** 같은 클러스터·등급·재알림 CVE이고 날짜가 7일 안이면 같은 이벤트로 본다. 판정 창이 밀리며 날짜가 바뀌는 경우를 흡수한다. */
        internal fun Notified.sameAs(e: AlertEvent) =
            clusterKey == e.clusterKey && level == e.level && trigger == e.trigger && ChronoUnit.DAYS.between(date, e.date).let { it in -7..7 }
    }

    fun run(prev: CollectorState, now: Instant): RunResult {
        val today = now.atZone(ZoneOffset.UTC).toLocalDate()
        val windowStart = today.minusDays(windowDays)
        val defaultSince = now.minus(Duration.ofDays(windowDays))
        val statuses = prev.sources.toMutableMap()
        fun since(name: String) = statuses[name]?.cursor?.let { runCatching { Instant.parse(it) }.getOrNull() } ?: defaultSince

        /** 소스 하나를 조회하고 상태를 남긴다. 실패하면 null(캐시 유지). */
        fun <T> poll(name: String, due: Boolean = true, block: () -> Poll<T>): Poll<T>? {
            if (!due) return null
            val old = statuses[name] ?: SourceState()
            return try {
                block().also {
                    // 받은 항목이 전부 형식 오류면 소스가 형식을 바꾼 것으로 보고 실패로 처리한다(빈 결과를 성공으로 넘기지 않음)
                    if (it.items.isEmpty() && it.skipped > 0) throw SourceFormatException(name, "모든 항목(${it.skipped}건)의 형식이 어긋남")
                    val warn = listOfNotNull(it.warning, if (it.skipped > 0) "형식이 어긋난 항목 ${it.skipped}건 건너뜀" else null)
                    statuses[name] = SourceState(now, now, null, warn.joinToString("; ").ifEmpty { null }, it.cursor)
                }
            } catch (e: Exception) {
                // 소스 하나의 어떤 실패(형식 변경, 예상 못 한 값)도 그 소스만 실패로 남기고 나머지는 계속한다
                statuses[name] = old.copy(lastAttemptAt = now, error = e.message ?: e.javaClass.simpleName)
                null
            } catch (e: StackOverflowError) {
                // 지나치게 깊게 중첩된 JSON·XML 응답
                statuses[name] = old.copy(lastAttemptAt = now, error = "응답 구조가 지나치게 깊음")
                null
            }
        }

        val nvdDue = statuses[Sources.NVD]?.lastSuccessAt?.let { Duration.between(it, now) >= Sources.NVD_INTERVAL } ?: true
        val kevPoll = poll(Sources.KEV) { sources.kev(statuses[Sources.KEV]?.cursor) }
            ?.let { p -> if (p.skipped > 0) p.copy(cursor = null) else p } // 형식 오류가 있었으면 다음 실행에서 전체를 다시 받는다
        val nvdPoll = poll(Sources.NVD, nvdDue) { sources.nvd(statuses[Sources.NVD]?.cursor?.let { runCatching { Instant.parse(it) }.getOrNull() }, defaultSince, now) }
        val kisaPoll = poll(Sources.KISA) { sources.kisa(prev.kisa.map { it.value }, now) }
        val thnPoll = poll(Sources.THN) { sources.thn(since(Sources.THN), now) }
        val bcPoll = poll(Sources.BC) { sources.bc(since(Sources.BC), now) }
        val dsPoll = poll(Sources.DS) { sources.ds(prev.news.map { it.value }, now) }

        // KEV는 카탈로그 전체가 오므로, 새로 받았으면 창 안의 항목으로 통째로 바꾼다(삭제된 항목 반영)
        val kev = if (kevPoll != null && !kevPoll.notModified) {
            val firstSeen = prev.kev.associate { it.value.cveId to it.firstSeen }
            kevPoll.items.map { Seen(it.value, it.url, firstSeen[it.value.cveId] ?: now) }
        } else {
            prev.kev
        }.filter { it.value.dateAdded >= windowStart.minusDays(7) }
            .sortedWith(compareBy({ it.value.dateAdded }, { it.value.cveId }))

        val nvd = merge(prev.nvd, nvdPoll?.items, now, replace = true) { c, _ -> c.id }
            .filter { it.value.published >= windowStart }
            .sortedWith(compareBy({ it.value.published }, { it.value.id }))
        val kisaMerged = merge(prev.kisa, kisaPoll?.items, now) { p, _ -> "${p.date}|${p.title}" }
            .filter { it.value.date >= windowStart }
            .sortedWith(compareBy({ it.value.date }, { it.value.title }))
        // 최근 공지의 본문(화면·조치 가이드 근거). 판정에는 쓰지 않으므로 실패해도 소스 상태는 그대로 둔다
        val failures = prev.bodyFailures.filterKeys { url -> kisaMerged.any { it.url == url } }.toMutableMap()
        val wanted = kisaMerged.filter {
            it.value.body.isEmpty() && it.value.date >= today.minusDays(feedDays + 1) &&
                it.url.startsWith("https://www.boho.or.kr/") && (failures[it.url] ?: 0) < KISA_BODY_TRIES
        }.sortedByDescending { it.value.date }.take(Sources.KISA_BODIES_PER_RUN).map { it.url }.toSet()
        val kisa = kisaMerged.map { s ->
            if (s.url !in wanted) return@map s
            try {
                s.copy(value = s.value.copy(body = sources.kisaBody(s.url)))
            } catch (e: Exception) {
                failures[s.url] = (failures[s.url] ?: 0) + 1
                s
            }
        }
        // 판정은 본문 앞 600자만 쓰므로 그만큼만 저장한다
        val newsIn = ((thnPoll?.items ?: emptyList()) + (bcPoll?.items ?: emptyList()) + (dsPoll?.items ?: emptyList()))
            .map { Linked(it.value.copy(text = it.value.text.takeCodePoints(600)), it.url) }
        val news = merge(prev.news, newsIn.takeIf { thnPoll != null || bcPoll != null || dsPoll != null }, now) { a, url -> url.ifEmpty { "${a.source}|${a.title}" } }
            .filter { it.value.publishedAt >= windowStart.atStartOfDay(ZoneOffset.UTC).toInstant() }
            .sortedWith(compareBy({ it.value.source }, { it.value.publishedAt }, { it.value.title }))

        // 판정
        val alertStart = today.minusDays(alertDays)
        // KISA 공지는 한국 날짜라 UTC 오늘보다 하루 앞설 수 있다(00~09시 KST). 판정 끝을 하루 늦춰 늦지 않게 한다
        val periodEnd = today.plusDays(1)
        // KEV는 캐시 전체(30일)를 넣어 판정 기간 앞의 이력도 잇는다(추출기는 periodStart-7일부터 받음)
        val signals = SignalExtractor(windowStart.plusDays(7), periodEnd).extract(
            kev.map { it.value },
            nvd.map { it.value },
            kisa.map { it.value },
            news.map { it.value },
        )
        val events = AlertEngine(ProductCatalog.names, alertStart, periodEnd).run(signals)

        // 이미 알린 것과 비교
        val fresh = events.filter { e -> prev.notified.none { it.sameAs(e) } }
        // CVE 목록이 없는 예전 기록은 지금 판정의 같은 이벤트 근거로 채운다(다른 클러스터의 같은 CVE를 잇는 데 쓴다)
        val backfilled = prev.notified.map { n ->
            if (n.cves.isNotEmpty()) n else events.firstOrNull { n.sameAs(it) }?.let { n.copy(cves = cvesOf(it, evidence(it, signals))) } ?: n
        }
        val notified = (backfilled + fresh.map { Notified(it.date, it.clusterKey, it.level, now, it.trigger, cvesOf(it, evidence(it, signals))) })
            .filter { it.date >= windowStart }
            .sortedWith(compareBy({ it.date }, { it.clusterKey }, { it.level }, { it.trigger }))
        val firstSeenOf = { e: AlertEvent -> notified.firstOrNull { it.sameAs(e) }?.firstSeen ?: now }

        val details = DetailBuilder(kev, nvd, kisa, news)
        val feedRaw = events.filter { it.date >= today.minusDays(feedDays) }
        /** 먼저 알린 같은 위협이 있으면 관계와 그 이벤트 id를 붙인다 */
        fun related(f: FeedEvent, e: AlertEvent, ev: List<Signal>, history: List<Notified>): FeedEvent =
            priorOf(e, cvesOf(e, ev), f.firstSeen, history).let { p -> relationOf(e, p).let { r -> if (r.isEmpty()) f else f.copy(relation = r, ref = idOf(p!!)) } }
        val feedEvents = feedRaw
            .map { e -> evidence(e, signals).let { ev -> related(FeedEvent.of(e, firstSeenOf(e), ev, details.titles(e, ev)), e, ev, notified) } }
            .sortedWith(compareByDescending<FeedEvent> { it.date }.thenByDescending { it.level }.thenBy { it.clusterKey })
        // 한 실행에서 같은 클러스터가 🟠와 🔴를 함께 얻으면(따라잡기) 🔴만 알린다. 기록에는 둘 다 남긴다
        val redNow = fresh.filter { it.level == Level.RED }.map { it.clusterKey }.toSet()
        val toPush = fresh.filterNot { it.level == Level.ORANGE && it.clusterKey in redNow }
        val live = prev.initialized && prev.rulesVersion == Rules.VERSION
        val newAlerts = if (live) toPush.map { e -> evidence(e, signals).let { ev -> related(FeedEvent.of(e, now, ev, details.titles(e, ev)), e, ev, backfilled) } } else emptyList()
        val followups = if (live) followUps(prev, toPush.map { it.clusterKey }.toSet(), details, feedEvents, today, now) else emptyList()

        val state = CollectorState(
            initialized = true,
            rulesVersion = Rules.VERSION,
            sources = statuses.toSortedMap(),
            kev = kev, nvd = nvd, kisa = kisa, news = news, notified = notified,
            bodyFailures = failures.toSortedMap(),
            followups = (prev.followups + followups.associate { it.clusterKey to now })
                .filterValues { Duration.between(it, now) <= Duration.ofDays(feedDays + 1) }.toSortedMap(),
        )
        val clusters = (feedRaw + newAlertsRaw(live, toPush)).groupBy { it.clusterKey }.mapValues { (key, es) ->
            details.detail(key, es.minOf { it.date }, es.flatMap { evidence(it, signals) }.distinct())
        }
        val feed = Feed(
            generatedAt = now,
            sources = Sources.ALL.map { FeedSource.of(it, statuses[it] ?: SourceState()) },
            events = feedEvents,
            clusters = clusters.toSortedMap(),
            incidents = details.incidents(
                today.minusDays(feedDays),
                feedRaw.filter { it.clusterKey.startsWith("INC:") }.groupBy { it.clusterKey }.mapValues { (_, es) -> es.maxOf { it.level }.name },
            ),
            notices = details.notices(today.minusDays(feedDays)),
            briefs = details.briefs(today.minusDays(feedDays)),
        )
        return RunResult(state, feed, newAlerts + followups)
    }

    /**
     * 이미 알린 취약점의 추가 보도: 알린 뒤(또는 마지막 추가 보도 알림 뒤) 처음 본 기사가 있으면 무음으로 한 번 알린다.
     * - 제품군·CVE 클러스터만(침해사고·KISA 공지는 제외), feed 기간 안에 알린 것만
     * - 이번 실행에 새 등급 알림이 나간 클러스터는 그 알림으로 충분하므로 건너뛴다
     * - 클러스터마다 [FOLLOWUP_GAP]에 한 번, 한 실행에 [MAX_FOLLOWUPS]건까지. 그 사이 기사는 다음 알림에 묶인다
     */
    private fun followUps(
        prev: CollectorState, pushedNow: Set<String>, details: DetailBuilder, feedEvents: List<FeedEvent>,
        today: java.time.LocalDate, now: Instant,
    ): List<FeedEvent> = prev.notified
        .filter { it.date >= today.minusDays(feedDays) && !it.clusterKey.startsWith("INC:") && !it.clusterKey.startsWith("KISA:") && it.clusterKey !in pushedNow }
        .groupBy { it.clusterKey }
        .mapNotNull { (key, ns) ->
            val last = prev.followups[key]
            if (last != null && Duration.between(last, now) < FOLLOWUP_GAP) return@mapNotNull null
            val latest = ns.maxWith(compareBy<Notified>({ it.date }, { it.level }, { it.firstSeen }))
            val since = listOfNotNull(ns.maxOf { it.firstSeen }, last).max()
            val articles = details.newsOf(key, latest.date.minusDays(7))
                .filter { it.firstSeen > since && Duration.between(it.value.publishedAt, now) <= FOLLOWUP_MAX_AGE }
            if (articles.isEmpty()) return@mapNotNull null
            val ref = idOf(latest)
            val title = feedEvents.firstOrNull { it.id == ref }?.title?.ifEmpty { null } ?: feedEvents.firstOrNull { it.clusterKey == key }?.title?.ifEmpty { null } ?: key
            val a = articles.last()
            FeedEvent(
                id = "FU|$ref|${now.epochSecond}", date = today, clusterKey = key, level = Level.ORANGE, signals = emptyList(),
                trigger = FeedEvent.FOLLOWUP, firstSeen = now, evidence = emptyList(), title = title,
                headline = "[${a.value.source}] ${a.value.title}" + if (articles.size > 1) " 외 ${articles.size - 1}건" else "",
                ref = ref,
            )
        }
        .sortedByDescending { it.ref.contains("|RED") }
        .take(MAX_FOLLOWUPS)

    private fun newAlertsRaw(live: Boolean, toPush: List<AlertEvent>) = if (live) toPush else emptyList()

    /** 이벤트 날짜까지 7일 안에 같은 클러스터에서 나온 신호. 카드의 근거로 쓴다. */
    private fun evidence(e: AlertEvent, signals: List<Signal>): List<Signal> =
        signals.filter { it.clusterKey == e.clusterKey && it.date <= e.date && it.date >= e.date.minusDays(7) }
            .sortedWith(compareBy({ it.date }, { it.kind }))

    /** 같은 키(항목, 링크로 정함)면 처음 본 시각은 유지한다. [replace]면 내용은 새로 받은 것으로 바꾼다(NVD 점수 갱신). */
    private fun <T> merge(
        old: List<Seen<T>>,
        fresh: List<Linked<T>>?,
        now: Instant,
        replace: Boolean = false,
        key: (T, String) -> String,
    ): List<Seen<T>> {
        if (fresh == null) return old
        val byKey = LinkedHashMap<String, Seen<T>>()
        for (s in old) byKey[key(s.value, s.url)] = s
        for (f in fresh) {
            val k = key(f.value, f.url)
            val existing = byKey[k]
            byKey[k] = when {
                existing == null -> Seen(f.value, f.url, now)
                replace -> Seen(f.value, f.url, existing.firstSeen)
                else -> existing
            }
        }
        return byKey.values.toList()
    }
}
