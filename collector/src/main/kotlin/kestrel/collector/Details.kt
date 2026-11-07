package kestrel.collector

import kestrel.rules.AlertEvent
import kestrel.rules.Article
import kestrel.rules.Incidents
import kestrel.rules.KevEntry
import kestrel.rules.KisaPost
import kestrel.rules.KisaTitleClassifier
import kestrel.rules.Level
import kestrel.rules.NewsTopics
import kestrel.rules.NvdCve
import kestrel.rules.ProductCatalog
import kestrel.rules.ProductNames
import kestrel.rules.Signal
import kestrel.rules.SignalKind
import kestrel.rules.SignalExtractor
import kestrel.rules.VendorAdvisory
import kestrel.rules.VendorExploit
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
    /** 이 클러스터의 마지막 소식(신호) 날짜, UTC. 등급이 그대로여도 기사·공지가 이어지면 늦어진다(v6.3) */
    val lastSignal: java.time.LocalDate? = null,
    /** 같은 사건을 다룬 다른 클러스터(보호나라 공지 ↔ 침해사고 보도, v6.4). 앱은 공지 카드 하나로 보인다 */
    val related: List<String> = emptyList(),
)

/**
 * 같은 사건을 다룬 보호나라 공지와 침해사고 보도를 잇는다(v6.4). 공지 제목의 영문 제품·회사 이름(4자 이상, 대문자로 시작)이
 * 침해사고 기사 제목에 나오고, 두 클러스터의 첫 날짜가 3일 안이면 같은 사건으로 본다. 예: "Synology NAS 대상 랜섬웨어 공격 주의 권고"와
 * "Synology warns of C3RB3R ransomware attacks targeting NAS devices"
 */
object RelatedClusters {
    /** 공지 제목의 영문 이름: 대문자로 시작하고 하이픈·점으로 이어진 것도 한 이름(D-Link, TP-Link, Node.js). 대소문자를 가려 맞춘다 */
    private val NAME = Regex("""(?<![A-Za-z0-9.-])[A-Z][A-Za-z0-9]*(?:[-.][A-Za-z0-9]+)*""")
    /** 큰 회사 이름과 사전 낱말(여러 사건에 두루 나와 같은 사건이라는 근거가 못 됨) */
    private val STOP = setOf(
        "KISA", "Microsoft", "Google", "Apple", "Windows", "Android", "Linux", "Chrome", "Samsung", "Cisco", "Oracle", "Amazon", "AWS", "Meta",
        "Link", "Point", "Trend", "Micro", "Open", "Active", "Directory", "Smart", "Utility", "Server", "Update", "Suite", "Security", "Cloud",
        "Exchange", "Office", "Service", "Services", "Network", "Manager", "Center", "Portal", "Web", "Mail", "Data", "Software", "System", "Systems",
        "Edge", "Mobile", "Pro", "Plus", "One", "API", "VPN", "SSL", "IoT", "SW", "AI", "PC", "IT",
    )
    /** 같은 사건이라는 두 번째 근거: 공지와 보도가 같은 공격 종류를 다룬다 */
    private val THEMES = listOf(
        Regex("랜섬웨어") to Regex("ransomware", RegexOption.IGNORE_CASE),
        Regex("악성코드|악성 ?파일") to Regex("malware|infostealer|stealer|backdoor|trojan", RegexOption.IGNORE_CASE),
        Regex("피싱|사칭") to Regex("phishing|impersonat", RegexOption.IGNORE_CASE),
        Regex("공급망|업데이트 (서버|파일) 변조|설치 파일") to Regex("supply[- ]chain|compromised|hijack|trojaniz", RegexOption.IGNORE_CASE),
        Regex("취약점|악용") to Regex("flaw|vulnerab|exploit|zero-day|0-day|CVE-", RegexOption.IGNORE_CASE),
        Regex("디도스|DDoS") to Regex("DDoS", RegexOption.IGNORE_CASE),
        Regex("유출|해킹|침해") to Regex("breach|leak|hack|stolen|exposed", RegexOption.IGNORE_CASE),
    )

    /** 공지 제목과 보도 제목이 같은 사건인가: 영문 이름이 하나 이상 같고, 이름이 둘 이상 같거나 공격 종류가 같다 */
    fun sameEvent(kisaTitle: String, newsTitles: String): Boolean {
        val names = NAME.findAll(kisaTitle).map { it.value }.filter { it.length >= 3 && it !in STOP }.toSet()
        val shared = names.filter { n -> Regex("""(?<![A-Za-z0-9])${Regex.escape(n)}(?![A-Za-z0-9])""").containsMatchIn(newsTitles) }
        if (shared.isEmpty()) return false
        return shared.size >= 2 || THEMES.any { (ko, en) -> ko.containsMatchIn(kisaTitle) && en.containsMatchIn(newsTitles) }
    }

    fun link(clusters: Map<String, ClusterDetail>, firstDate: Map<String, LocalDate>): Map<String, ClusterDetail> {
        val kisa = clusters.filterKeys { it.startsWith("KISA:") }
        val inc = clusters.filterKeys { it.startsWith("INC:") }
        val pairs = mutableListOf<Pair<String, String>>()
        for ((kk, kc) in kisa) {
            val kisaTitles = kc.docs.filter { it.kind == "kisa" }.map { it.title }
            if (kisaTitles.isEmpty()) continue
            for ((ik, ic) in inc) {
                val a = firstDate[kk] ?: continue
                val b = firstDate[ik] ?: continue
                if (kotlin.math.abs(java.time.temporal.ChronoUnit.DAYS.between(a, b)) > 3) continue
                val titles = ic.docs.filter { it.kind == "news" }.joinToString(" ") { it.title }
                if (kisaTitles.any { sameEvent(it, titles) }) pairs += kk to ik
            }
        }
        if (pairs.isEmpty()) return clusters
        val out = clusters.toMutableMap()
        for ((kk, ik) in pairs) {
            val kc = out.getValue(kk)
            val ic = out.getValue(ik)
            // 공지 카드에 보도 기사도 원문으로 붙인다(앱은 공지 카드 하나로 보일 수 있다). 자리가 없어 기사를 하나도 못 붙이면 잇지 않는다
            val news = ic.docs.filter { it.kind == "news" && kc.docs.none { d -> d.url == it.url } }
            val room = DetailBuilder.MAX_DOCS - kc.docs.size
            if (room <= 0 && news.isNotEmpty()) continue
            out[kk] = kc.copy(related = (kc.related + ik).distinct(), docs = kc.docs + news.take(room.coerceAtLeast(0)))
            out[ik] = ic.copy(related = (ic.related + kk).distinct())
        }
        return out
    }
}

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
 * 일반 보안 뉴스 한 건(뉴스 탭). 공개 저장소에 싣는 것이라 본문은 넣지 않고 제목·링크·출처·시각만(저작권).
 * [topic]: NewsTopics.Topic id, [ai]: AI 보안이면 하위 분류 id(아니면 빈 문자열),
 * [major]: 주요(긴급 표현 · 두 매체 이상 · AI 공급망·서비스 사고·공격), [sources]: 같은 이야기를 다룬 매체 수
 */
data class NewsItem(val at: Instant, val source: String, val title: String, val url: String, val topic: String, val ai: String, val major: Boolean, val sources: Int)

/**
 * 캐시한 원자료로 클러스터 상세·침해사고·생활 보안 공지를 만든다. 수집 결과만으로 정해지므로 실행마다 같다.
 * 크기를 묶어 둔다: 문서는 클러스터당 [MAX_DOCS]개, 문서 본문은 종류별 상한까지.
 */
class DetailBuilder(
    private val kev: List<Seen<KevEntry>>,
    private val nvd: List<Seen<NvdCve>>,
    private val kisa: List<Seen<KisaPost>>,
    private val news: List<Seen<Article>>,
    /** 제조사 보안 공지(v6.3) */
    private val vendor: List<Seen<VendorAdvisory>> = emptyList(),
    /** 뉴스 탭에 싣는 기사(판정·위협 원문에 쓰지 않는 GeekNews 포함). 없으면 [news] */
    private val tabNews: List<Seen<Article>> = news,
) {
    companion object {
        const val MAX_DOCS = 10
        /** 제조사 공지 요약 길이. 공개 feed라 앞부분만 둔다(기사처럼 저작물이므로 짧게, 전체는 "원문 보기") */
        const val VENDOR_EXCERPT = 300
        const val MAX_CVES = 12
        const val MAX_RANGES = 30
        const val MAX_BRIEFS = 80
        const val MAX_INCIDENTS = 30
        /** 뉴스 탭에 싣는 최대 건수(최신순). 한 건 약 300바이트 */
        const val MAX_NEWS = 200
        /** 한 매체가 뉴스 탭을 채우지 않게(11월 첫 주: 데일리시큐 118/200건) */
        const val MAX_NEWS_PER_SOURCE = 70
        private val NEWS_ORDER = compareByDescending<NewsItem> { it.at }.thenBy { it.title }

        /**
         * 뉴스 [max]건 고르기(최신순 입력): 매체마다 [perSource]건까지, 주제 "기타"는 주요가 아니면 뒤로 미룬 뒤,
         * 자리가 남으면 미룬 기사로 채운다. 결과는 다시 최신순.
         */
        fun capNews(items: List<NewsItem>, max: Int, perSource: Int): List<NewsItem> {
            val count = HashMap<String, Int>()
            val first = ArrayList<NewsItem>()
            val later = ArrayList<NewsItem>()
            for (n in items) {
                val c = count[n.source] ?: 0
                if (c < perSource && (n.major || n.topic != NewsTopics.Topic.OTHER.id)) { first += n; count[n.source] = c + 1 } else later += n
            }
            val picked = first.take(max)
            return (picked + later.take(max - picked.size)).sortedWith(NEWS_ORDER)
        }

        /** 같은 이야기를 묶을 때 빼는 흔한 낱말(이것만 겹치면 같은 이야기로 보지 않는다) */
        val STORY_STOP = setOf(
            "Your", "You", "CVSS", "SOC", "How", "Why", "What", "When", "Webinar", "Fake", "Patches", "Patch", "Flaws", "Bug", "Bugs", "Exploited",
            "Actively", "Attackers", "Attacker", "Run", "Code", "Operations", "ThreatsDay", "Recap", "Ways", "Already", "Operate", "Browser",
            "Devices", "Device", "Phone", "Phones", "Apps", "App", "Mobile", "Network", "Networks", "Report", "Researchers", "Warns", "Warn",
        )
        /**
         * 공개 feed에 싣는 원문 길이. 기사는 요약 한두 문장(저작권: 공개 저장소에 본문을 옮기지 않는다), 보호나라 공지는 조치 안내 앞부분.
         * 전체 원문은 "원문 보기"와 AI의 원문 링크 열람(web_fetch)으로 본다. NVD·KEV(미국 정부 자료)는 그대로 둔다
         */
        const val NEWS_EXCERPT = 200
        const val KISA_EXCERPT = 1000
        private val CVE = Regex("""CVE-\d{4}-\d{4,7}""")
        /** S8 근거 끝에 붙은 CVE 목록 */
        private val CVE_TAIL = Regex("""( CVE-\d{4}-\d{4,7})+$""")
        private val KST = ZoneOffset.ofHours(9)
        private val INCIDENT_KINDS = setOf(SignalKind.S7, SignalKind.S7S, SignalKind.S7K, SignalKind.S7K_MAJOR)
        private val KEV_KINDS = setOf(SignalKind.KEV_S6, SignalKind.KEV_S6_OLD, SignalKind.KEV_OTHER)

        /** 제품군 이름(ProductCatalog)의 표시 이름. */
        val DISPLAY = mapOf(
            "PaloAlto" to "Palo Alto Networks", "Citrix" to "Citrix NetScaler", "F5" to "F5 BIG-IP", "CheckPoint" to "Check Point",
            "Exchange" to "Microsoft Exchange", "SharePoint" to "Microsoft SharePoint", "ApacheCore" to "Apache",
            "PHPcore" to "PHP", "WebLogic" to "Oracle WebLogic", "NetWeaver" to "SAP NetWeaver",
            "NodeJS" to "Node.js", "OracleEBS" to "Oracle E-Business Suite·PeopleSoft", "VeloCloud" to "VeloCloud SD-WAN",
            "LoadMaster" to "Progress LoadMaster", "ServU" to "SolarWinds Serv-U", "WingFTP" to "Wing FTP Server",
            "Collabora" to "Collabora·Nextcloud·ownCloud", "ScreenConnect" to "ConnectWise ScreenConnect", "NCentral" to "N-able N-central",
            "WindowsServer" to "Windows 서버·Active Directory", "Chrome" to "Google Chrome",
        )

        fun display(group: String): String = DISPLAY[group] ?: group

        private val PRODUCT_TAIL = Regex("""\s+[–—+|:]\s+|\s+-\s+|\s*\(""")

        /** 긴 제품 이름을 앞부분만: "Project Manager – AI Powered …" → "Project Manager", 40자가 넘으면 낱말 단위로 */
        fun shortProduct(name: String): String {
            val head = name.split(PRODUCT_TAIL).first().trim()
            if (head.length <= 40) return head
            val out = StringBuilder()
            for (w in head.split(' ')) { if (out.length + w.length + 1 > 40) break; if (out.isNotEmpty()) out.append(' '); out.append(w) }
            return out.toString() + "…"
        }

        private val PRODUCT_SPLIT = Regex("""\s+(and|&)\s+|\s*[,;/(]\s*""")

        /**
         * KEV 제품 이름 중 제목에 붙일 부분: 첫 제품만("A and B" → A), 제품군 표시 이름에 이미 있는 낱말은 빼고,
         * 40자가 넘으면 낱말 단위로 줄인다. 예: "Citrix NetScaler" + "NetScaler ADC" → "ADC"
         */
        fun productSuffix(base: String, key: String, product: String): String {
            val have = base.lowercase().split(' ').toSet() + key.lowercase()
            val first = product.split(PRODUCT_SPLIT).first().trim()
            val words = first.split(Regex("\\s+")).filter { it.isNotBlank() && it.lowercase() !in have }
            val out = StringBuilder()
            for (w in words) {
                if (out.length + w.length + 1 > 40) return (out.toString() + "…").trim()
                if (out.isNotEmpty()) out.append(' ')
                out.append(w)
            }
            return out.toString().clip(40)
        }

        private fun day(i: Instant): LocalDate = i.atZone(ZoneOffset.UTC).toLocalDate()
        private fun start(d: LocalDate): Instant = d.atStartOfDay(KST).toInstant()
    }

    /** 이벤트 제목(규칙으로 만든 한국어 제목)과 대표 원문 제목. */
    fun titles(e: AlertEvent, evidence: List<Signal>): Pair<String, String> {
        val key = e.clusterKey
        val kinds = evidence.map { it.kind }.toSet()
        val maxScore = evidence.filter { it.kind == SignalKind.S1 || it.kind == SignalKind.S1_8 }
            .mapNotNull { it.detail.split(' ').getOrNull(1)?.toDoubleOrNull() }.maxOrNull()
        val headline = evidence.lastOrNull { it.kind == SignalKind.S8 }?.detail?.replace(CVE_TAIL, "")
            ?: evidence.lastOrNull { it.kind.code.startsWith("S2") || it.kind == SignalKind.KISA_ROUTINE }?.detail
            ?: evidence.lastOrNull { it.kind == SignalKind.NEWS1_URGENT || it.kind == SignalKind.S3 }?.detail?.substringBefore(" / ")
            ?: ""
        val title = when {
            e.trigger.isNotEmpty() -> "${withKevProduct(key, e.trigger)} 새 취약점 실제 악용 (${e.trigger})"
            key.startsWith("KISA:") -> evidence.firstOrNull { it.kind.code.startsWith("S2") || it.kind == SignalKind.KISA_ROUTINE }?.detail ?: key.removePrefix("KISA:")
            key.startsWith("INC:") -> "침해사고: " + (evidence.firstOrNull { it.kind in INCIDENT_KINDS }?.detail?.substringBefore(" / ")?.replace(Regex("^\\[[A-Z]+] "), "") ?: key.removePrefix("INC:"))
            else -> {
                val phrase = when {
                    SignalKind.KEV_S6 in kinds || SignalKind.KEV_S6_OLD in kinds || SignalKind.KEV_OTHER in kinds -> "취약점 실제 악용 (CISA KEV 등재)"
                    SignalKind.S8 in kinds -> "취약점 실제 악용 (제조사 공지)"
                    SignalKind.S2A in kinds -> "KISA 긴급 보안 공지"
                    SignalKind.S1 in kinds -> "치명적 원격 취약점" + (maxScore?.let { " (CVSS $it)" } ?: "")
                    SignalKind.S3 in kinds -> "긴급 보도 확산"
                    SignalKind.S1_8 in kinds -> "고위험 원격 취약점" + (maxScore?.let { " (CVSS $it)" } ?: "")
                    SignalKind.S2B in kinds -> "KISA 주의 권고"
                    SignalKind.NEWS1_URGENT in kinds -> "긴급 보도"
                    else -> "보안 업데이트 권고"
                }
                // KEV 등재면 업체 단위 클러스터(Cisco 등)라도 어느 제품인지 보이게 KEV의 제품 이름을 붙인다
                val kevCve = evidence.lastOrNull { it.kind in KEV_KINDS }?.detail?.let { CVE.find(it)?.value }
                "${if (kevCve != null && phrase.startsWith("취약점 실제 악용")) withKevProduct(key, kevCve) else productOf(key)} $phrase"
            }
        }
        return title.clip(120) to headline.clip(200)
    }

    /** 제품군 이름 뒤에 KEV 항목의 제품 이름(40자까지)을 붙인다. 제품 이름이 이미 제품군 이름을 담거나 KEV에 없으면 제품군 이름만 */
    private fun withKevProduct(key: String, cve: String): String {
        val base = productOf(key)
        if (key !in ProductCatalog.names) return base
        val product = kev.firstOrNull { it.value.cveId == cve }?.value?.product?.trim().orEmpty()
        val extra = productSuffix(base, key, product)
        return if (extra.isEmpty()) base else "$base $extra"
    }

    private fun productOf(key: String): String = when {
        key in ProductCatalog.names -> display(key)
        // KEV 이름(제조사·제품이 겹치면 한 번만), 없으면 NVD 영향 범위의 제조사·제품(WordPress 플러그인·테마는 그렇게 표시). 그것도 없으면 CVE 번호
        CVE.matches(key) -> kev.firstOrNull { it.value.cveId == key }?.value?.let { ProductNames.kev(it.vendorProject, it.product) }
            ?: nvd.firstOrNull { it.value.id == key }?.value?.let { ProductNames.nvd(it, ::shortProduct) }?.ifEmpty { null }
            ?: key
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
                key.startsWith("INC:") -> key.removePrefix("INC:").let { k ->
                    k in Incidents.tokens(a.value.title) || Incidents.koreanIncident(a.value.title, a.value.text) == k || Incidents.supplyKey(a.value.title) == k
                }
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
        // 공급망 침해(S7S)만으로 묶인 클러스터는 이름이 흔한 제품명(예: Claude)일 수 있어, 공급망 침해 기사만 싣는다
        val supplyOnly = evidence.isNotEmpty() && evidence.all { it.kind == SignalKind.S7S }
        val newsHits = newsOf(key, from).filter { !supplyOnly || Incidents.isSupply(it.value.title) }
        // 제조사 공지: 이 클러스터로 묶이는 실제 악용 공지와, 근거에 나온 CVE를 다룬 공지(같은 업체의 무관한 공지는 싣지 않는다)
        val evidenceCves = (listOf(key) + evidence.map { it.detail }).flatMap { t -> CVE.findAll(t).map { it.value } }.toSet()
        val vendorHits = vendor.filter { v ->
            v.value.date >= from && (
                (VendorExploit.of(v.value) && SignalExtractor.vendorKey(v.value) == key) || v.value.cves.any { it in evidenceCves }
                )
        }.sortedByDescending { it.value.date }.take(3)

        // CVE: 근거 신호 → KEV → KISA 본문 → 기사 순서로 모은다
        val cves = LinkedHashSet<String>()
        if (CVE.matches(key)) cves += key
        evidence.forEach { s -> CVE.findAll(s.detail).forEach { cves += it.value } }
        kevHits.forEach { cves += it.cveId }
        kisaHits.forEach { p -> CVE.findAll(p.value.body).forEach { cves += it.value } }
        newsHits.forEach { a -> CVE.findAll(a.value.title).forEach { cves += it.value } }
        vendorHits.forEach { v -> cves += v.value.cves }
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
        vendorHits.forEach { v ->
            docs += SourceDoc("vendor:${docs.size}", "vendor", "[${v.value.vendor}] ${v.value.title}", v.url, start(v.value.date),
                v.value.text.ifEmpty { v.value.title }.clip(VENDOR_EXCERPT))
        }
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
        val koreanInfo = korean.mapNotNull { a -> Incidents.koreanIncident(a.value.title, a.value.text)?.let { it to a } }
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

    /**
     * 일반 보안 뉴스: 최근 [since]부터의 기사 가운데 [exclude](취약점 알림 원문·침해사고 기사로 이미 보이는 주소)를 뺀 것. 최신순 최대 [MAX_NEWS]건.
     * 같은 이야기를 다룬 매체 수는 48시간 안에 고유명사가 겹치는 다른 매체 기사로 센다.
     */
    fun news(since: LocalDate, exclude: Set<String>): List<NewsItem> {
        val recent = tabNews.filter { day(it.value.publishedAt) >= since }
        val tokens = recent.associate { it.url to (Incidents.tokens(it.value.title) - STORY_STOP) }
        return recent.filter { it.url !in exclude }.map { a ->
            val mine = tokens[a.url].orEmpty()
            // GeekNews는 다른 매체 기사를 다시 소개하므로 "여러 매체 보도"에 세지 않는다
            val sameStory = recent.filter { b ->
                b.value.source != a.value.source && b.value.source != GeekNewsAtomParser.SOURCE_CODE &&
                    Duration.between(b.value.publishedAt, a.value.publishedAt).abs() <= Duration.ofHours(48) &&
                    (tokens[b.url].orEmpty() intersect mine).isNotEmpty()
            }.map { it.value.source }.toSet()
            val topic = if (a.value.source == GeekNewsAtomParser.SOURCE_CODE) NewsTopics.geekTopic(a.value.title) else NewsTopics.topic(a.value.title, a.value.text)
            val ai = NewsTopics.aiKind(a.value.title, a.value.text)
            // 업계 소식(칼럼·출시·행사 등)은 주요로 올리지 않는다
            val major = topic != NewsTopics.Topic.INDUSTRY && topic != NewsTopics.Topic.AI_TREND && (UrgentText.isUrgent(a.value) || sameStory.isNotEmpty() ||
                ai in setOf(NewsTopics.AiKind.SUPPLY, NewsTopics.AiKind.SERVICE, NewsTopics.AiKind.ATTACK))
            NewsItem(a.value.publishedAt, a.value.source, a.value.title.clip(200), a.url, topic.id, ai?.id.orEmpty(), major, 1 + sameStory.size)
        }.sortedWith(NEWS_ORDER).let { capNews(it, MAX_NEWS, MAX_NEWS_PER_SOURCE) }
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
