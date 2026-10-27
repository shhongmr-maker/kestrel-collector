package kestrel.rules

import java.time.Duration
import java.time.LocalDate
import java.time.ZoneOffset

/**
 * CISA KEV 카탈로그 항목 하나. 판정에는 앞의 네 값만 쓴다.
 * 나머지는 화면과 조치 가이드의 근거로만 쓰며, 예전 state에는 없을 수 있어 기본값이 빈 값이다.
 */
data class KevEntry(
    val cveId: String,
    val vendorProject: String,
    val product: String,
    val dateAdded: LocalDate,
    val name: String = "",
    val shortDescription: String = "",
    val requiredAction: String = "",
    val dueDate: LocalDate? = null,
    /** "Known" 또는 "Unknown" */
    val ransomware: String = "",
)

/**
 * 영향 범위 하나(NVD 설정의 CPE 일치 조건 또는 CNA가 낸 affected 항목). 버전 문자열은 원문 그대로다.
 * [exact]가 있으면 그 버전 하나, 아니면 [from]부터 [lessThan] 미만(또는 [lessThanOrEqual] 이하)이다.
 */
data class VersionRange(
    val vendor: String,
    val product: String,
    val exact: String? = null,
    val from: String? = null,
    val fromExcluding: Boolean = false,
    val lessThan: String? = null,
    val lessThanOrEqual: String? = null,
)

/** NVD CVE 하나. CVSS는 v4.0 → v3.1 → v3.0 순서로 처음 있는 지표 하나만 쓴다. */
data class NvdCve(
    val id: String,
    val published: LocalDate,
    val description: String,
    val cvssScore: Double?,
    val cvssVector: String?,
    /** 화면·조치 가이드 근거용. 판정에는 쓰지 않는다. */
    val affected: List<VersionRange> = emptyList(),
    /** 참고 링크(벤더 권고 등). 판정에는 쓰지 않는다. */
    val references: List<String> = emptyList(),
)

/** 보호나라 보안공지 게시글 하나. [body]는 화면·조치 가이드 근거용 본문(받은 경우만)이고 판정에는 쓰지 않는다. */
data class KisaPost(val date: LocalDate, val title: String, val body: String = "") {
    companion object {
        private val LEADING_NO = Regex("""^\d+\s+""")
        private val TRAILING_VIEWS_DATE = Regex("""\s[\d,]+\s\d{4}-\d{2}-\d{2}$""")

        /** 게시판 목록의 한 줄("2581 제목 40,539 2026-10-24")에서 번호·조회수·날짜를 떼어낸다. */
        fun fromBoardRow(date: LocalDate, row: String): KisaPost =
            KisaPost(date, row.replaceFirst(LEADING_NO, "").replaceFirst(TRAILING_VIEWS_DATE, ""))
    }
}


/**
 * 원자료를 하루 단위 [Signal] 목록으로 바꾼다. research/shadow/engine.py의 신호 생성 단계와 같다.
 *
 * 출력 순서도 Python과 같게 유지한다(KEV → NVD → KISA → 뉴스 → 침해사고). 같은 날짜 안의 순서가 이벤트 순서에 영향을 주기 때문이다.
 */
class SignalExtractor(
    private val periodStart: LocalDate,
    private val periodEnd: LocalDate,
    /** 공개 2년이 넘은 CVE의 KEV 추가를 [SignalKind.KEV_S6_OLD](주목)로 낮춘다. */
    private val oldKevDowngrade: Boolean = false,
) {
    /** [nvd]는 핵심 제품군 설명에 걸리는 CVE와, 제품군 밖이라도 S1(CVSS 9 이상·원격·무인증·무상호작용)인 CVE다. */
    fun extract(kev: List<KevEntry>, nvd: List<NvdCve>, kisa: List<KisaPost>, news: List<Article>): List<Signal> {
        val alias = kevAlias(kev)
        return fromKev(kev, alias) + fromNvd(nvd, alias) + fromKisa(kisa) + fromNews(news, alias)
    }

    fun fromKev(entries: List<KevEntry>, alias: Map<String, String> = kevAlias(entries)): List<Signal> = entries.mapNotNull { v ->
        val d = v.dateAdded
        if (d < periodStart.minusDays(7) || d > periodEnd) return@mapNotNull null
        val group = ProductCatalog.groupOfKev(v.vendorProject, v.product, v.name)
        val kind = when {
            group == null -> SignalKind.KEV_OTHER
            oldKevDowngrade && v.cveId.substring(4, 8).toInt() <= d.year - 2 -> SignalKind.KEV_S6_OLD
            else -> SignalKind.KEV_S6
        }
        Signal(d, group ?: alias[v.cveId] ?: v.cveId, kind, "${v.cveId} ${v.vendorProject} ${v.product}")
    }

    /**
     * 제품군마다(목록 순서) 설명문이 맞는 CVE로 S1·S1_8·체인 신호를 낸다.
     * v6: 어느 제품군에도 맞지 않는 CVE도 S1이면 신호를 낸다(키 = CVE, 같은 날 KEV 묶음이면 그 대표 CVE).
     */
    fun fromNvd(cves: List<NvdCve>, alias: Map<String, String> = emptyMap()): List<Signal> {
        val out = mutableListOf<Signal>()
        for (group in ProductCatalog.groups) {
            val byDay = LinkedHashMap<LocalDate, MutableList<NvdCve>>()
            for (c in cves) {
                if (!group.textPattern.containsMatchIn(c.description)) continue
                val score = c.cvssScore ?: continue
                val vector = c.cvssVector ?: continue
                byDay.getOrPut(c.published) { mutableListOf() } += c
                when (CvssRule.classify(score, vector)) {
                    SignalKind.S1 -> out += Signal(c.published, group.name, SignalKind.S1, "${c.id} $score")
                    SignalKind.S1_8 -> out += Signal(c.published, group.name, SignalKind.S1_8, "${c.id} $score")
                    else -> {}
                }
            }
            for ((d, sameDay) in byDay) {
                val chain = ChainRule.findChain(sameDay.map { ChainRule.Cve(it.id, it.cvssVector!!, it.description) })
                if (chain != null) out += Signal(d, group.name, SignalKind.S1, "chain ${chain.first}+${chain.second}")
            }
        }
        for (c in cves) {
            val score = c.cvssScore ?: continue
            val vector = c.cvssVector ?: continue
            if (ProductCatalog.groupOfText(c.description) != null) continue
            if (CvssRule.classify(score, vector) == SignalKind.S1) out += Signal(c.published, alias[c.id] ?: c.id, SignalKind.S1, "${c.id} $score")
        }
        return out
    }

    fun fromKisa(posts: List<KisaPost>): List<Signal> = posts.map { p ->
        val group = ProductCatalog.groupOfKisaTitle(p.title)
        Signal(p.date, group ?: "KISA:" + p.title.takeCodePoints(30), KisaTitleClassifier.classify(p.title), p.title)
    }

    fun fromNews(articles: List<Article>, alias: Map<String, String> = emptyMap()): List<Signal> {
        val tagged = tag(articles, alias)
        val out = mutableListOf<Signal>()

        val byKey = LinkedHashMap<String, MutableList<Tagged>>()
        for (t in tagged) for (k in t.keys) byKey.getOrPut(k) { mutableListOf() } += t
        // v5: 키마다 처음 한 번이 아니라 조건이 맞는 날마다 하루 한 번 낸다. 같은 제품군의 다음 사건을 놓치지 않기 위해서다
        for ((key, list) in byKey) {
            val sorted = list.sortedBy { it.article.publishedAt }
            val s3Days = HashSet<LocalDate>()
            val urgentDays = HashSet<LocalDate>()
            for ((j, a) in sorted.withIndex()) {
                val day = a.article.day()
                if (day !in s3Days) {
                    val window = sorted.subList(0, j + 1)
                        .filter { Duration.between(it.article.publishedAt, a.article.publishedAt) <= Duration.ofHours(24) }
                    val bySource = window.groupingBy { it.article.source }.eachCount()
                    if (window.any { it.urgent } && (bySource.size >= 2 || bySource.values.max() >= 3)) {
                        s3Days += day
                        out += Signal(day, key, SignalKind.S3,
                            window.take(3).joinToString(" / ") { "[${it.article.source}] ${it.article.title.takeCodePoints(70)}" })
                    }
                }
                if (a.urgent && urgentDays.add(day)) {
                    out += Signal(day, key, SignalKind.NEWS1_URGENT, "[${a.article.source}] ${a.article.title.takeCodePoints(90)}")
                }
            }
        }

        out += Incidents.find(tagged.filter { !it.korean && it.group == null && Incidents.isIncident(it.article.title) }.map { it.article })
        out += Incidents.findKorean(articles.filter { it.source == UrgentText.KOREAN_SOURCE })
        return out
    }

    internal data class Tagged(val article: Article, val group: String?, val keys: List<String>, val urgent: Boolean, val korean: Boolean)

    private fun tag(articles: List<Article>, alias: Map<String, String>): List<Tagged> {
        class Raw(val a: Article, val group: String?, val cves: List<String>, val names: List<String>)
        val raws = articles.map { a ->
            val head = a.title + " " + a.text.takeCodePoints(600)
            Raw(
                a, ProductCatalog.groupOfText(a.title),
                CVE.findAll(head).map { it.value }.toSortedSet().toList(),
                NAMED.findAll(head).map { it.groupValues[1] }.filter { it !in NAMED_STOP }.toSortedSet().toList(),
            )
        }
        // 이름 → CVE: 이름과 CVE가 하나만 함께 나온 기사에서 배운다. 가장 많이 함께 나온 CVE(같으면 먼저 본 것)
        val named = LinkedHashMap<String, LinkedHashMap<String, Int>>()
        for (r in raws) {
            if (r.cves.size != 1) continue
            for (n in r.names) named.getOrPut(n) { LinkedHashMap() }.merge(r.cves[0], 1, Int::plus)
        }
        return raws.map { r ->
            val linked = r.cves.toSet() + r.names.mapNotNull { n -> named[n]?.entries?.maxByOrNull { it.value }?.key }
            val keys = listOfNotNull(r.group) + linked.map { alias[it] ?: it }.distinct().sortedWith(CVE_ORDER)
            Tagged(r.a, r.group, keys, UrgentText.isUrgent(r.a), r.a.source == UrgentText.KOREAN_SOURCE)
        }
    }

    companion object {
        private val CVE = Regex("""CVE-\d{4}-\d{4,7}""")
        /** 이름 붙은 취약점: PHP2Shell, wp2shell, Log4Shell, CitrixBleed 같은 이름 */
        private val NAMED = Regex("""\b([A-Za-z][A-Za-z0-9]{0,20}2[Ss]hell|[A-Z][A-Za-z0-9]{1,20}(?:Shell|Bleed))\b""")
        private val NAMED_STOP = setOf("PowerShell", "WebShell", "ReverseShell", "BindShell", "OpenShell")
        /** CVE 번호 순서(연도, 일련번호) */
        val CVE_ORDER: Comparator<String> = compareBy({ it.substring(4, 8).toInt() }, { it.substring(9).toInt() })

        /**
         * 핵심 제품군 밖 KEV는 같은 벤더·제품·날짜를 한 묶음으로 보고 가장 작은 CVE를 대표 키로 쓴다(v6).
         * 같은 날 함께 오른 CVE(예: wp2shell 두 건)가 따로 알림이 되지 않게 하고, 기사·NVD 키도 그 대표로 맞춘다.
         */
        fun kevAlias(kev: List<KevEntry>): Map<String, String> {
            val groups = LinkedHashMap<Triple<String, String, LocalDate>, MutableList<String>>()
            for (v in kev) {
                if (ProductCatalog.groupOfKev(v.vendorProject, v.product, v.name) != null) continue
                groups.getOrPut(Triple(v.vendorProject.trim(), v.product.trim(), v.dateAdded)) { mutableListOf() } += v.cveId
            }
            val out = HashMap<String, String>()
            for (ids in groups.values) {
                val head = ids.minWith(CVE_ORDER)
                for (c in ids) out[c] = head
            }
            return out
        }
    }
}

/**
 * 침해사고.
 * - S7(해외): 다른 매체의 침해 기사 두 건이 48시간 안에 같은 고유명사를 공유하고, 대형 사고 표현이 있으면 성립(🟠).
 * - S7K(국내): 한국어 매체의 국내 기관 침해사고 기사 한 건(🟠). 금융·통신·공공·대규모면 S7K_MAJOR(🔴).
 * v6: 제목 판별을 넓히고(공급망 침해·유출·탈취) 법 집행·칼럼·가정형("could") 기사는 뺐다(docs/10).
 */
object Incidents {
    private val INCIDENT = Regex(
        """\bbreach(es|ed)?\b|data leak|\bleak(s|ed)?\b|stolen|\bsteal(s|ing)?\b|data theft|exfiltrat|""" +
            """ransomware attack|hit by ransomware|\bransom\b|extort|cyber ?attack|\bhack(ed|s)?\b|compromis(e|ed|es)\b|""" +
            """supply[- ]chain (attack|hack|breach|compromise)|outage|goes offline|disrupts? .{0,30}(utilit|water|hospital|operations|services)|""" +
            """exposed .{0,40}(data|records|information|credentials|keys)""",
        RegexOption.IGNORE_CASE,
    )
    private val NOT_INCIDENT = Regex(
        """arrest|sentenc|prison|plead|extradit|charged|indict|takedown|dismantl|seiz|sanction|""" +
            """webinar|recap|bulletin|ThreatsDay|playbook|\bhow\b|\bwhy\b|guide|CTF|Pwn2Own|study|survey|""" +
            """disrupts? .{0,40}(operation|service|network|botnet|infrastructure|gang)|""" +
            """\bcould\b|\bcan\b|\blets? (attackers|anyone|hackers)|\bmay (let|allow)|\bwould\b""",
        RegexOption.IGNORE_CASE,
    )
    private val MAJOR = Regex(
        """million|\b\d{1,3},\d{3}\b|\d+K\b|thousand|records|customers|users|accounts|repos|repositories|tenants|""" +
            """employees|patients|students|members|government|ministry|agency|hospital|health|airline|airport|bank|""" +
            """exchange|crypto|\$\d|telecom|carrier|water|power|energy|grid|utilit|supply[- ]chain|npm|PyPI|package|""" +
            """installer|extension|plugin|source code|Korea|nationwide|ransomware|outage""",
        RegexOption.IGNORE_CASE,
    )
    private val PROPER = Regex("""\b[A-Z][A-Za-z0-9&'.-]{2,}\b""")
    private val STOP = (
        "The A An And Of In On For To With New Hackers Hacker Data Breach Breaches Breached Ransomware Attack Attacks Cyberattack " +
            "Says Over After From By Its Their Million Customers Users Group Gang Claims Hit Hits Stolen Leak Leaked Exposes Exposed " +
            "Confirms Discloses Company Firm US UK EU Security Systems Outage Chinese Russian Iranian North Korean South State " +
            "FBI CISA Police API VPN OAuth RCE Critical Flaw Vulnerability Zero-Day Hack Hacked Compromised Compromise Supply Chain " +
            "Steal Steals Theft Inside More Are How Why What Week Weekly Microsoft Google Apple Amazon Linux Windows Android AI " +
            "Malicious Chrome Edge Extensions Extension Plugins Plugin npm PyPI Package Packages Credentials Accounts Access Agent " +
            "Agents Tokens Token Server Servers Cloud"
        ).split(' ').toSet()

    // 국내(한국어 제목). 실제로 국내 기관이 당한 사고만 고르고 통계·정책·주장·수사·칼럼·취약점 기사는 뺀다
    private val INC_KO = Regex(
        "해킹|유출|침해 ?사고|랜섬웨어|탈취|디도스|DDoS|사이버 ?공격|불법 ?접근|비인가 ?접근|무단 ?접근|접속 장애|서비스 장애|" +
            "공급망 공격|악성코드 (유포|감염)|도용|노출",
        RegexOption.IGNORE_CASE,
    )
    private val ACTUAL_KO = Regex(
        "(해킹|침해 ?사고|랜섬웨어 (감염|공격)|사이버 ?공격).{0,40}(유출|탈취|확인|피해|마비|중단|장애)|" +
            "(개인정보|고객 ?정보|회원 ?정보|신용정보|정보)\\s?유출 (확인|사고|피해|정황|인정)|" +
            "(개인정보|고객 ?정보|회원 ?정보|신용정보|직원 정보)\\s?유출|해킹(으로|에|당해|당한| 피해)|침해사고",
        RegexOption.IGNORE_CASE,
    )
    private val NOT_INC_KO = Regex(
        "검거|구속|기소|선고|송치|징역|체포|칼럼|연재|소설|웨비나|세미나|컨퍼런스|콘퍼런스|워크숍|출시|협력|MOU|협약|교육|훈련|" +
            "모의|가이드|백서|보고서|분석|정책|의원|법안|국감|국정감사|간담회|토론회|포럼|특허|수상|선정|획득|인터뷰|기고|" +
            "예방|대응 ?방안|주의 ?당부|주의보|피싱|스미싱|사칭|전망|동향|트렌드|설문|조사 결과|솔루션|플랫폼 공개|채용|과태료|과징금|처분|제재|" +
            "시도|건수|올해|현황|통계|위원장|원장|점검|경고|우려|가능성|주장|용의자|배후|추적|수사|권고|후속조치|완료|파기|교훈|사례|대비|" +
            "다크웹|판매|게시|해외|분쟁조정|집단|평균|건 중|비용|자격증|과정|인사이트|탐지 가능|긴급회의|당국|급증|상반기|하반기|조사 착수|" +
            "취약점|RCE|CVE|증가",
        RegexOption.IGNORE_CASE,
    )
    private val SEVERE_KO = Regex(
        "은행|카드|생명|보험|증권|저축은행|캐피탈|금융|텔레콤|통신사|\\bKT\\b|SKT|LG ?U\\+|유심|USIM|" +
            "\\d[\\d,.]*\\s?만\\s?(명|건)|\\d{1,3}(,\\d{3}){2,}|억\\s?건|부처|정부24|국세청|건강보험|병원",
        RegexOption.IGNORE_CASE,
    )
    private val KO_LEAD_TRIM = Regex("""^(\[[^\]]{1,10}\]\s*)+""")
    private val KO_PARTICLE = Regex("(에서|으로|,|…|·)$")
    private val KO_PARTICLE1 = Regex("(은|는|이|가|의|에|로|도|과|와)$")
    private val KO_SPLIT = Regex("[\\s\u00a0,…·]")
    private val KO_QUOTES = Regex("[‘’“”\"']")
    private val KO_BAD_START = Regex("""^[\d\[(]""")
    private const val QUOTE_CHARS = "\"'‘’“”"
    private val KO_GENERIC = setOf(
        "국내", "금융권", "공공기관", "정부", "한국", "북한", "중국", "러시아", "일본", "미국", "AI", "의료기관", "기업", "해커", "해킹조직",
        "랜섬웨어", "단독", "긴급", "속보", "주의", "이란", "대만", "유럽", "영국", "프랑스", "독일", "호주", "인도", "베트남", "글로벌",
        "전", "세계", "중소", "악성", "상반기", "하반기", "보안기업", "물류업체", "개인정보위", "금융당국", "네덜란드", "캐나다", "싱가포르",
        "보험사", "은행권", "카드사", "통신사", "병원", "대학", "학교",
    )

    /** 해외 침해사고 제목인가(제품군 여부는 부르는 쪽이 본다). */
    fun isIncident(title: String): Boolean = INCIDENT.containsMatchIn(title) && !NOT_INCIDENT.containsMatchIn(title)

    /** 제목의 고유명사(대문자로 시작하는 낱말, 흔한 낱말 제외). 같은 사건을 다룬 기사를 묶는 데 쓴다. */
    fun tokens(title: String): Set<String> = PROPER.findAll(title).map { it.value }.filter { it.trimEnd('.') !in STOP }.toSet()

    /** [incidents]: 해외 침해사고 기사(입력 순서 유지). */
    fun find(incidents: List<Article>): List<Signal> {
        val out = mutableListOf<Signal>()
        for ((i, a) in incidents.withIndex()) {
            for (b in incidents.subList(i + 1, incidents.size)) {
                if (b.source == a.source) continue
                if (Duration.between(a.publishedAt, b.publishedAt).abs() > Duration.ofHours(48)) continue
                val shared = tokens(a.title) intersect tokens(b.title)
                if (shared.isEmpty() || !MAJOR.containsMatchIn(a.title + " " + b.title)) continue
                val later = maxOf(a.publishedAt, b.publishedAt)
                out += Signal(
                    later.atZone(ZoneOffset.UTC).toLocalDate(), "INC:" + shared.sorted().first(), SignalKind.S7,
                    "[${a.source}] ${a.title.takeCodePoints(70)} / [${b.source}] ${b.title.takeCodePoints(70)}",
                )
            }
        }
        return out
    }

    /** 한국어 제목 맨 앞의 기관·회사 이름(대략). 한 글자 조사는 이름 끝 글자와 구분할 수 없어 떼지 않는다(티켓베이). */
    fun koreanEntity(title: String): String {
        val t = KO_LEAD_TRIM.replace(title, "").trim().trim { it in QUOTE_CHARS }
        var w = t.split(KO_SPLIT, limit = 2)[0]
        w = KO_PARTICLE.replace(w, "")
        w = KO_QUOTES.replace(w, "")
        return if (w.codePointCount(0, w.length) >= 2) w else ""
    }

    /** 국내 침해사고 기사면 기관 이름, 아니면 null. */
    fun koreanIncident(title: String): String? {
        if (!INC_KO.containsMatchIn(title) || !ACTUAL_KO.containsMatchIn(title) || NOT_INC_KO.containsMatchIn(title)) return null
        val e = koreanEntity(title)
        // 일반 명사(국내·금융권·AI 등)는 한 글자 조사를 뗀 형태도 본다("AI가")
        if (e.isEmpty() || e in KO_GENERIC || KO_PARTICLE1.replace(e, "") in KO_GENERIC || KO_BAD_START.containsMatchIn(e)) return null
        return e
    }

    fun isSevereKorean(title: String): Boolean = SEVERE_KO.containsMatchIn(title)

    /** [korean]: 한국어 매체 기사(입력 순서 유지). */
    fun findKorean(korean: List<Article>): List<Signal> = korean.mapNotNull { a ->
        val e = koreanIncident(a.title) ?: return@mapNotNull null
        Signal(a.day(), "INC:$e", if (isSevereKorean(a.title)) SignalKind.S7K_MAJOR else SignalKind.S7K, "[${a.source}] ${a.title.takeCodePoints(90)}")
    }
}

internal fun Article.day(): LocalDate = publishedAt.atZone(ZoneOffset.UTC).toLocalDate()

/** Python의 s[:n]과 같게 코드 포인트 기준으로 자른다. */
internal fun String.takeCodePoints(n: Int): String {
    val count = codePointCount(0, length)
    return if (count <= n) this else substring(0, offsetByCodePoints(0, n))
}
