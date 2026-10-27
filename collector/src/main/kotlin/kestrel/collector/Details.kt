package kestrel.collector

import kestrel.rules.AlertEvent
import kestrel.rules.Article
import kestrel.rules.Incidents
import kestrel.rules.KevEntry
import kestrel.rules.KisaPost
import kestrel.rules.KisaTitleClassifier
import kestrel.rules.Level
import kestrel.rules.NvdCve
import kestrel.rules.ProductCatalog
import kestrel.rules.Signal
import kestrel.rules.SignalKind
import kestrel.rules.UrgentText
import kestrel.rules.VersionRange
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

/** 클러스터(제품군·CVE·KISA 공지·침해사고) 하나의 상세. 화면, 원문 링크, Claude 조치 가이드의 근거로 쓴다. 판정에는 쓰지 않는다. */
data class ClusterDetail(
    /** "vuln"(제품군·CVE), "kisa"(KISA 공지), "incident"(침해사고) */
    val category: String,
    /** 표시용 제품명. 없으면 빈 문자열 */
    val product: String,
    val cves: List<String>,
    val cvss: CvssInfo?,
    val kev: List<KevInfo>,
    val ranges: List<CveRange>,
    val docs: List<SourceDoc>,
)

data class CvssInfo(val cve: String, val score: Double, val vector: String)

data class KevInfo(
    val cve: String,
    val name: String,
    val dateAdded: LocalDate,
    val dueDate: LocalDate?,
    val requiredAction: String,
    val ransomware: String,
)

data class CveRange(val cve: String, val range: VersionRange)

/**
 * 근거 문서 하나. [id]는 feed 안에서 유일하고 Claude 인용의 출처 표시로 쓴다.
 * [kind]: "nvd" · "kev" · "kisa" · "news". [text]는 원문 일부(일반 텍스트)다.
 */
data class SourceDoc(val id: String, val kind: String, val title: String, val url: String, val date: Instant, val text: String)

/** 침해사고 보도 묶음. 같은 고유명사를 공유하는 기사끼리 묶는다. [level]은 S7 판정이 났으면 "RED", 아니면 빈 문자열. */
data class IncidentInfo(val key: String, val title: String, val level: String, val firstReported: Instant, val articles: List<SourceDoc>)

/** 생활 보안 공지(KISA 피싱·스미싱·사칭 주의보). 판정 대상이 아니라 앱 설정에서 켠 경우만 보인다. */
data class NoticeInfo(val date: LocalDate, val title: String, val url: String)

/**
 * 보안 소식 한 건(알림 대상이 아닌 것도 포함). 앱의 "보안 소식" 목록과 내 자산 관련 소식 표시에 쓴다.
 * [kind]: "kisa-urgent"(긴급 공지) · "kisa-caution"(주의 권고) · "kisa-phishing"(피싱·사칭) · "kisa-update"(업데이트 권고) · "news-urgent"(긴급 보도)
 * [group]: 핵심 제품군이면 그 표시 이름(아니면 빈 문자열). [cves]: 제목·본문에 나온 CVE.
 */
data class BriefInfo(val at: Instant, val kind: String, val source: String, val title: String, val url: String, val group: String, val cves: List<String>)

/**
 * 캐시한 원자료로 클러스터 상세·침해사고·생활 보안 공지를 만든다. 수집 결과만으로 정해지므로 실행마다 같다.
 * 크기를 묶어 둔다: 문서는 클러스터당 [MAX_DOCS]개, 문서 본문은 종류별 상한까지.
 */
class DetailBuilder(
    private val kev: List<Seen<KevEntry>>,
    private val nvd: List<Seen<NvdCve>>,
    private val kisa: List<Seen<KisaPost>>,
    private val news: List<Seen<Article>>,
) {
    companion object {
        const val MAX_DOCS = 10
        const val MAX_CVES = 12
        const val MAX_RANGES = 30
        const val MAX_BRIEFS = 80
        const val MAX_INCIDENTS = 30
        /**
         * 공개 feed에 싣는 원문 길이. 기사는 요약 한두 문장(저작권: 공개 저장소에 본문을 옮기지 않는다), 보호나라 공지는 조치 안내 앞부분.
         * 전체 원문은 "원문 보기"와 AI의 원문 링크 열람(web_fetch)으로 본다. NVD·KEV(미국 정부 자료)는 그대로 둔다
         */
        const val NEWS_EXCERPT = 200
        const val KISA_EXCERPT = 1000
        private val CVE = Regex("""CVE-\d{4}-\d{4,7}""")
        private val KST = ZoneOffset.ofHours(9)
        private val INCIDENT_KINDS = setOf(SignalKind.S7, SignalKind.S7K, SignalKind.S7K_MAJOR)

        /** 제품군 이름(ProductCatalog)의 표시 이름. */
        val DISPLAY = mapOf(
            "PaloAlto" to "Palo Alto Networks", "Citrix" to "Citrix NetScaler", "F5" to "F5 BIG-IP", "CheckPoint" to "Check Point",
            "Exchange" to "Microsoft Exchange", "SharePoint" to "Microsoft SharePoint", "ApacheCore" to "Apache",
            "PHPcore" to "PHP", "WebLogic" to "Oracle WebLogic", "NetWeaver" to "SAP NetWeaver",
            "NodeJS" to "Node.js", "OracleEBS" to "Oracle E-Business Suite·PeopleSoft", "VeloCloud" to "VeloCloud SD-WAN",
            "LoadMaster" to "Progress LoadMaster", "ServU" to "SolarWinds Serv-U", "WingFTP" to "Wing FTP Server",
            "Collabora" to "Collabora·Nextcloud·ownCloud", "ScreenConnect" to "ConnectWise ScreenConnect", "NCentral" to "N-able N-central",
        )

        fun display(group: String): String = DISPLAY[group] ?: group

        private fun day(i: Instant): LocalDate = i.atZone(ZoneOffset.UTC).toLocalDate()
        private fun start(d: LocalDate): Instant = d.atStartOfDay(KST).toInstant()
    }

    /** 이벤트 제목(규칙으로 만든 한국어 제목)과 대표 원문 제목. */
    fun titles(e: AlertEvent, evidence: List<Signal>): Pair<String, String> {
        val key = e.clusterKey
        val kinds = evidence.map { it.kind }.toSet()
        val maxScore = evidence.filter { it.kind == SignalKind.S1 || it.kind == SignalKind.S1_8 }
            .mapNotNull { it.detail.split(' ').getOrNull(1)?.toDoubleOrNull() }.maxOrNull()
        val headline = evidence.lastOrNull { it.kind.code.startsWith("S2") || it.kind == SignalKind.KISA_ROUTINE }?.detail
            ?: evidence.lastOrNull { it.kind == SignalKind.NEWS1_URGENT || it.kind == SignalKind.S3 }?.detail?.substringBefore(" / ")
            ?: ""
        val title = when {
            e.trigger.isNotEmpty() -> "${productOf(key)} 새 취약점 실제 악용 (${e.trigger})"
            key.startsWith("KISA:") -> evidence.firstOrNull { it.kind.code.startsWith("S2") || it.kind == SignalKind.KISA_ROUTINE }?.detail ?: key.removePrefix("KISA:")
            key.startsWith("INC:") -> "침해사고: " + (evidence.firstOrNull { it.kind in INCIDENT_KINDS }?.detail?.substringBefore(" / ")?.replace(Regex("^\\[[A-Z]+] "), "") ?: key.removePrefix("INC:"))
            else -> {
                val phrase = when {
                    SignalKind.KEV_S6 in kinds || SignalKind.KEV_S6_OLD in kinds || SignalKind.KEV_OTHER in kinds -> "취약점 실제 악용 (CISA KEV 등재)"
                    SignalKind.S2A in kinds -> "KISA 긴급 보안 공지"
                    SignalKind.S1 in kinds -> "치명적 원격 취약점" + (maxScore?.let { " (CVSS $it)" } ?: "")
                    SignalKind.S3 in kinds -> "긴급 보도 확산"
                    SignalKind.S1_8 in kinds -> "고위험 원격 취약점" + (maxScore?.let { " (CVSS $it)" } ?: "")
                    SignalKind.S2B in kinds -> "KISA 주의 권고"
                    SignalKind.NEWS1_URGENT in kinds -> "긴급 보도"
                    else -> "보안 업데이트 권고"
                }
                "${productOf(key)} $phrase"
            }
        }
        return title.clip(120) to headline.clip(200)
    }

    private fun productOf(key: String): String = when {
        key in ProductCatalog.names -> display(key)
        CVE.matches(key) -> kev.firstOrNull { it.value.cveId == key }?.value?.let { "${it.vendorProject} ${it.product}" } ?: key
        else -> key
    }

    /** 클러스터 상세. [evidence]는 그 클러스터의 모든 이벤트 근거를 합친 것이다. */
    /** 클러스터에 붙는 기사([from] 날짜 이후, 오래된 것부터): 제품군은 제목의 제품, CVE는 제목·본문의 번호, 침해사고는 회사 이름으로 맞춘다 */
    fun newsOf(key: String, from: LocalDate): List<Seen<Article>> {
        val group = key.takeIf { it in ProductCatalog.names }
        return news.filter { a ->
            day(a.value.publishedAt) >= from && when {
                group != null -> ProductCatalog.groupOfText(a.value.title) == group
                CVE.matches(key) -> key in a.value.title || key in a.value.text
                key.startsWith("INC:") -> key.removePrefix("INC:").let { k -> k in Incidents.tokens(a.value.title) || Incidents.koreanIncident(a.value.title) == k }
                else -> false
            }
        }.sortedBy { it.value.publishedAt }
    }

    fun detail(key: String, firstDate: LocalDate, evidence: List<Signal>): ClusterDetail {
        val from = firstDate.minusDays(7)
        val group = key.takeIf { it in ProductCatalog.names }
        val pattern = group?.let { g -> ProductCatalog.groups.first { it.name == g }.textPattern }

        val kevHits = kev.map { it.value }.filter { k ->
            k.dateAdded >= from && (k.cveId == key || (group != null && ProductCatalog.groupOfKev(k.vendorProject, k.product, k.name) == group))
        }
        val kisaHits = kisa.filter { p ->
            p.value.date >= from && (
                (group != null && ProductCatalog.groupOfKisaTitle(p.value.title) == group) ||
                    (key.startsWith("KISA:") && evidence.any { it.detail == p.value.title }) ||
                    (CVE.matches(key) && key in p.value.body)
                )
        }
        val newsHits = newsOf(key, from)

        // CVE: 근거 신호 → KEV → KISA 본문 → 기사 순서로 모은다
        val cves = LinkedHashSet<String>()
        if (CVE.matches(key)) cves += key
        evidence.forEach { s -> CVE.findAll(s.detail).forEach { cves += it.value } }
        kevHits.forEach { cves += it.cveId }
        kisaHits.forEach { p -> CVE.findAll(p.value.body).forEach { cves += it.value } }
        newsHits.forEach { a -> CVE.findAll(a.value.title).forEach { cves += it.value } }
        val cveList = cves.take(MAX_CVES)

        val nvdById = nvd.associateBy { it.value.id }
        val nvdHits = cveList.mapNotNull { nvdById[it] }
            .filter { pattern == null || pattern.containsMatchIn(it.value.description) || it.value.id == key }
        val cvss = nvdHits.mapNotNull { c -> c.value.cvssScore?.let { s -> c.value.cvssVector?.let { CvssInfo(c.value.id, s, it) } } }
            .maxByOrNull { it.score }
        // NVD 설정에는 그 제품을 품은 다른 제품(예: PHP를 쓰는 장비 펌웨어)도 나온다. 클러스터 제품과 이름이 맞는 범위를 앞에 둔다
        val productWord = (group?.let { display(it) } ?: "").substringBefore(' ').lowercase()
        val ranges = nvdHits.flatMap { c -> c.value.affected.map { CveRange(c.value.id, it) } }.distinct()
            .sortedBy { r -> if (productWord.isNotEmpty() && (productWord in r.range.product.lowercase() || productWord in r.range.vendor.lowercase())) 0 else 1 }
            .take(MAX_RANGES)

        val docs = mutableListOf<SourceDoc>()
        kisaHits.sortedByDescending { it.value.date }.forEach { p ->
            docs += SourceDoc("kisa:${p.value.date}:${docs.size}", "kisa", p.value.title, p.url, start(p.value.date), p.value.body.ifEmpty { p.value.title }.clip(KISA_EXCERPT))
        }
        kevHits.forEach { k ->
            val text = listOf(k.shortDescription, "필수 조치: ${k.requiredAction}".takeIf { k.requiredAction.isNotEmpty() },
                k.dueDate?.let { "조치 기한(미국 연방기관): $it" }, "랜섬웨어 악용: ${k.ransomware}".takeIf { k.ransomware.isNotEmpty() })
                .filterNotNull().filter { it.isNotEmpty() }.joinToString("\n")
            docs += SourceDoc("kev:${k.cveId}", "kev", "CISA KEV · ${k.cveId} ${k.name}".trim(), "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                start(k.dateAdded), text.ifEmpty { "${k.vendorProject} ${k.product}" }.clip(1200))
        }
        nvdHits.forEach { c ->
            val v = c.value
            val rangeText = v.affected.take(10).joinToString("\n") { "영향: ${it.vendor} ${it.product} ${rangeLabel(it)}" }
            val refs = v.references.take(3).joinToString("\n") { "참고: $it" }
            docs += SourceDoc("nvd:${v.id}", "nvd", "NVD · ${v.id}" + (v.cvssScore?.let { " · CVSS $it" } ?: ""), c.url, start(v.published),
                listOf(v.description, rangeText, refs).filter { it.isNotEmpty() }.joinToString("\n").clip(1800))
        }
        newsHits.takeLast(5).reversed().forEach { a ->
            docs += SourceDoc("news:${docs.size}", "news", "[${a.value.source}] ${a.value.title}", a.url, a.value.publishedAt, a.value.text.ifEmpty { a.value.title }.clip(NEWS_EXCERPT))
        }

        val category = when {
            key.startsWith("INC:") -> "incident"
            key.startsWith("KISA:") -> "kisa"
            else -> "vuln"
        }
        val product = when {
            group != null -> display(group)
            CVE.matches(key) -> productOf(key).takeIf { it != key } ?: nvdHits.firstOrNull()?.value?.affected?.firstOrNull()?.product.orEmpty()
            else -> ""
        }
        return ClusterDetail(category, product, cveList, cvss, kevHits.map { KevInfo(it.cveId, it.name, it.dateAdded, it.dueDate, it.requiredAction, it.ransomware) },
            ranges, docs.take(MAX_DOCS))
    }

    /**
     * 침해사고 목록(침해사고 탭).
     * - 해외: 제품군이 없는 침해 제목 기사를 같은 고유명사·48시간 안으로 묶는다.
     * - 국내(한국어 매체): 국내 기관 침해사고 기사를 같은 기관 이름으로 묶는다(v6).
     * [levels]는 판정이 난 침해사고 클러스터 키와 등급("RED"/"ORANGE").
     */
    fun incidents(since: LocalDate, levels: Map<String, String>): List<IncidentInfo> {
        val recent = news.filter { day(it.value.publishedAt) >= since }.sortedBy { it.value.publishedAt }
        val korean = recent.filter { it.value.source == UrgentText.KOREAN_SOURCE }
        val foreign = recent.filter {
            it.value.source != UrgentText.KOREAN_SOURCE && Incidents.isIncident(it.value.title) && ProductCatalog.groupOfText(it.value.title) == null
        }
        val groups = mutableListOf<MutableList<Seen<Article>>>()
        for (a in foreign) {
            val tokens = Incidents.tokens(a.value.title)
            val g = groups.firstOrNull { g ->
                g.any { b -> Duration.between(b.value.publishedAt, a.value.publishedAt).abs() <= Duration.ofHours(48) && (Incidents.tokens(b.value.title) intersect tokens).isNotEmpty() }
            }
            if (g != null) g += a else groups += mutableListOf(a)
        }
        val foreignInfo = groups.map { g ->
            val shared = g.map { Incidents.tokens(it.value.title) }.reduce { x, y -> if ((x intersect y).isEmpty()) x else x intersect y }
            val level = shared.mapNotNull { levels["INC:$it"] }.maxByOrNull { if (it == "RED") 1 else 0 }.orEmpty()
            info("INC:" + (shared.sorted().firstOrNull() ?: g.first().value.title.clip(30)), level, g)
        }
        val koreanInfo = korean.mapNotNull { a -> Incidents.koreanIncident(a.value.title)?.let { it to a } }
            .groupBy({ it.first }, { it.second })
            .map { (entity, g) -> info("INC:$entity", levels["INC:$entity"].orEmpty(), g) }
        return (foreignInfo + koreanInfo).sortedByDescending { it.firstReported }.take(MAX_INCIDENTS)
    }

    private fun info(key: String, level: String, g: List<Seen<Article>>) = IncidentInfo(
        key = key,
        title = g.first().value.title.clip(200),
        level = level,
        firstReported = g.first().value.publishedAt,
        articles = g.takeLast(5).mapIndexed { i, a ->
            SourceDoc("inc:$i", "news", "[${a.value.source}] ${a.value.title}", a.url, a.value.publishedAt, a.value.text.ifEmpty { a.value.title }.clip(NEWS_EXCERPT))
        },
    )

    /** 보안 소식: 최근 [since]부터의 KISA 공지 전부와 긴급 표현이 있는 기사. 최신순 최대 [MAX_BRIEFS]건. */
    fun briefs(since: LocalDate): List<BriefInfo> {
        val fromKisa = kisa.filter { it.value.date >= since }.map { p ->
            val kind = when (KisaTitleClassifier.classify(p.value.title)) {
                SignalKind.S2A -> "kisa-urgent"
                SignalKind.S2B -> "kisa-caution"
                SignalKind.S2C -> "kisa-phishing"
                else -> "kisa-update"
            }
            BriefInfo(start(p.value.date), kind, "보호나라", p.value.title.clip(200), p.url,
                ProductCatalog.groupOfKisaTitle(p.value.title)?.let(::display).orEmpty(),
                CVE.findAll(p.value.title + " " + p.value.body).map { it.value }.distinct().take(6).toList())
        }
        val fromNews = news.filter { day(it.value.publishedAt) >= since && UrgentText.isUrgent(it.value) }.map { a ->
            BriefInfo(a.value.publishedAt, "news-urgent", a.value.source, a.value.title.clip(200), a.url,
                ProductCatalog.groupOfText(a.value.title)?.let(::display).orEmpty(),
                CVE.findAll(a.value.title + " " + a.value.text).map { it.value }.distinct().take(6).toList())
        }
        return (fromKisa + fromNews).sortedWith(compareByDescending<BriefInfo> { it.at }.thenBy { it.title }).take(MAX_BRIEFS)
    }

    /** 생활 보안 공지(S2c: 피싱·스미싱·사칭). */
    fun notices(since: LocalDate): List<NoticeInfo> = kisa.filter { it.value.date >= since && KisaTitleClassifier.classify(it.value.title) == SignalKind.S2C }
        .sortedByDescending { it.value.date }.take(10).map { NoticeInfo(it.value.date, it.value.title, it.url) }
}

/** 영향 범위를 사람이 읽는 문자열로("8.3.0 이상 8.3.36 미만", "9.3.7 미만", "= 2.1"). */
fun rangeLabel(r: VersionRange): String = when {
    r.exact != null -> "= ${r.exact}"
    else -> listOfNotNull(
        r.from?.let { if (r.fromExcluding) "$it 초과" else "$it 이상" },
        r.lessThan?.let { "$it 미만" },
        r.lessThanOrEqual?.let { "$it 이하" },
    ).joinToString(" ").ifEmpty { "모든 버전" }
}
