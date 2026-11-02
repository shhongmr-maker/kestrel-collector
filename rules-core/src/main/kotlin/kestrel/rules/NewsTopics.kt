package kestrel.rules

/**
 * 보안 뉴스 주제 분류(규칙, 수집기와 앱이 함께 쓴다). 제목(과 있으면 요약)만 보고 정한다.
 * 순서대로 처음 맞는 주제 하나: AI 보안 → 랜섬웨어·악성코드 → 피싱·사기 → 정책·제재·수사 → 유출·침해 → 위협 동향 → 취약점·패치 → 기타.
 * (침해사고로 묶인 기사는 수집기가 뉴스에서 빼므로, 유출·침해는 알림·침해사고에 들지 않은 보도다)
 * AI 보안은 하위 분류([AiKind])를 함께 낸다.
 */
object NewsTopics {
    enum class Topic(val id: String, val label: String) {
        AI("ai", "AI 보안"),
        RANSOMWARE("ransomware", "랜섬웨어·악성코드"),
        PHISHING("phishing", "피싱·사기"),
        POLICY("policy", "정책·제재·수사"),
        BREACH("breach", "유출·침해"),
        THREAT("threat", "위협 동향·APT"),
        VULN("vuln", "취약점·패치"),
        OTHER("other", "기타");

        companion object { fun of(id: String) = entries.firstOrNull { it.id == id } ?: OTHER }
    }

    /** AI 보안의 하위 분류 */
    enum class AiKind(val id: String, val label: String) {
        SUPPLY("supply", "AI 공급망"),
        SERVICE("service", "AI 서비스 사고"),
        PRODUCT("product", "AI 제품 취약점"),
        ATTACK("attack", "AI를 쓴 공격"),
        POLICY("policy", "AI 정책·규제"),
        GENERAL("general", "AI 일반");

        companion object { fun of(id: String) = entries.firstOrNull { it.id == id } }
    }

    private fun rx(p: String) = Regex(p, RegexOption.IGNORE_CASE)

    /**
     * AI 제품·서비스 이름(제목에 "AI"가 없어도 AI 관련으로 본다). 늘릴 때는 여기만 고친다.
     * 단어 경계는 영문·숫자로만 정한다(Android의 \b는 한글을 글자로 보지 않아 어긋날 수 있다)
     */
    val AI_PRODUCTS = listOf(
        "OpenAI", "ChatGPT", "GPT-?[345]", "Anthropic", "Claude", "Gemini", "Copilot", "Hugging ?Face", "Langflow", "LangChain", "LlamaIndex",
        "Ollama", "OpenHands", "Open WebUI", "LiteLLM", "Flowise", "ComfyUI", "vLLM", "Cursor", "DeepSeek", "Mistral AI", "Perplexity", "Midjourney",
    )
    private const val L = "(?<![A-Za-z0-9])"
    private const val R = "(?![A-Za-z0-9])"
    private val AI_WORDS = rx(
        "${L}(AI|A\\.I\\.|LLMs?|GenAI|agentic|deepfakes?|deep-fakes?|prompt injection|MCP|machine learning|large language models?)$R|" +
            "AI-(powered|driven|generated|based|enabled)|AI (agents?|models?|assistants?|tools?|coding)|" +
            "인공지능|생성형|딥페이크|챗GPT|챗지피티|프롬프트 인젝션|거대언어모델|대규모 언어 모델|AI 에이전트|AI 기반|AI 모델|AI 코딩",
    )
    private val AI_PRODUCT = rx(AI_PRODUCTS.joinToString("|") { "$L$it$R" })

    private val SUPPLY = rx("extensions?|확장|plugins?|플러그인|packages?|패키지|${L}npm$R|PyPI|${L}models? (repo|hub)|malicious model|악성 모델|marketplace|supply.chain|공급망|backdoor(ed)? (extension|package)")
    private val SERVICE = rx("breach|leak|exposed|exposes|exposing|stolen|유출|노출|API keys?|키 (유출|탈취)|conversations? (leak|exposed)|대화 (기록|내용)")
    private val PRODUCT = rx("vulnerab|flaws?|${L}bugs?$R|${L}RCE$R|CVE-|zero-day|0-day|취약점|prompt injection|프롬프트 인젝션|jailbreak|탈옥|exploit")
    private val ATTACK = rx("hackers? (use|using|abuse)|threat actors? (use|using)|AI-powered|AI-driven|automated attacks?|deepfakes?|딥페이크|AI (phishing|scams?)|AI (피싱|사기)|악용|weaponi[sz]")
    private val POLICY_AI = rx("${L}(act|law|bill|regulations?|rules?|guidelines?|executive order|ban)$R|법안|기본법|규제|가이드라인|정책|지침|금지")

    private val RANSOMWARE = rx("ransomware|랜섬웨어|malware|악성코드|악성 ?앱|infostealer|stealer|trojan|트로이|wiper|botnet|봇넷|backdoor|백도어|worm|웜|spyware|스파이웨어|RAT$R|cryptojack|채굴")
    private val PHISHING = rx("phish|피싱|스미싱|smishing|vishing|보이스피싱|scams?$R|사기|fraud|사칭|impersonat|BEC$R|business email compromise|메신저 피싱")
    private val POLICY = rx("sanction|제재|arrest|체포|검거|기소|charged|indicted|sentenced|선고|징역|extradit|송환|seized|압수|takedown|dismantl|disrupt|해체|수사|경찰|FBI|Europol|CISA (order|directive)|법안|규제|과징금|fine[sd]?$R|regulation|${L}law$R|정책|의무화|가이드라인")
    private val BREACH = rx("breach|leak|exposed|stolen|hacked|compromised|유출|해킹|침해|탈취|노출")
    private val THREAT = rx("${L}APT$R|state-sponsored|nation-state|국가 배후|해킹 그룹|hacking group|threat actors?|campaign|캠페인|espionage|첩보|spying|cyberattack|사이버 공격|공격 그룹|DDoS|디도스|Lazarus|라자루스|김수키|Kimsuky")
    private val VULN = rx("vulnerab|flaws?|${L}bugs?$R|${L}CVE-|zero-day|0-day|제로데이|취약점|patch|패치|보안 업데이트|security update|exploit|${L}RCE$R")

    fun isAi(title: String, text: String = ""): Boolean {
        val s = "$title $text"
        return AI_WORDS.containsMatchIn(s) || AI_PRODUCT.containsMatchIn(s)
    }

    /** AI 보안의 하위 분류. AI 관련이 아니면 null */
    fun aiKind(title: String, text: String = ""): AiKind? {
        if (!isAi(title, text)) return null
        // 제목을 먼저 본다(요약에는 다른 이야기가 섞일 수 있다)
        for (s in listOf(title, "$title $text")) {
            when {
                SUPPLY.containsMatchIn(s) && (RANSOMWARE.containsMatchIn(s) || rx("malicious|악성|compromised|hijack|탈취|변조").containsMatchIn(s)) -> return AiKind.SUPPLY
                SERVICE.containsMatchIn(s) -> return AiKind.SERVICE
                PRODUCT.containsMatchIn(s) -> return AiKind.PRODUCT
                ATTACK.containsMatchIn(s) -> return AiKind.ATTACK
                POLICY_AI.containsMatchIn(s) -> return AiKind.POLICY
            }
        }
        return AiKind.GENERAL
    }

    fun topic(title: String, text: String = ""): Topic {
        if (isAi(title, text)) return Topic.AI
        // 제목으로 먼저 정하고, 제목만으로 못 정하면 요약까지 본다
        for (s in listOf(title, "$title $text")) {
            when {
                RANSOMWARE.containsMatchIn(s) -> return Topic.RANSOMWARE
                PHISHING.containsMatchIn(s) -> return Topic.PHISHING
                POLICY.containsMatchIn(s) -> return Topic.POLICY
                BREACH.containsMatchIn(s) -> return Topic.BREACH
                THREAT.containsMatchIn(s) -> return Topic.THREAT
                VULN.containsMatchIn(s) -> return Topic.VULN
            }
        }
        return Topic.OTHER
    }
}
