package kestrel.rules

/** 보호나라 보안공지 제목 분류. 피싱·사칭을 먼저 걸러낸다(사칭 공지에도 "주의 권고"가 붙기 때문). */
object KisaTitleClassifier {
    private val PHISHING = Regex("피싱|스미싱|큐싱|사칭|스팸")
    private val STRONG = Regex("대응 수칙|임시 조치|강화 요청|합동사이버보안권고|위협정보 공유|긴급")
    private val CAUTION = Regex("주의 ?권고|주의 안내|보안 점검 권고")

    fun classify(title: String): SignalKind = when {
        PHISHING.containsMatchIn(title) -> SignalKind.S2C
        STRONG.containsMatchIn(title) -> SignalKind.S2A
        CAUTION.containsMatchIn(title) -> SignalKind.S2B
        else -> SignalKind.KISA_ROUTINE
    }
}

/** CVSS 점수와 벡터 문자열로 S1 / S1_8을 정한다. v4.0과 v3.x 벡터 모두 같은 지표 이름(AV, PR, UI)을 쓴다. */
object CvssRule {
    fun classify(score: Double, vector: String): SignalKind? {
        val network = "AV:N" in vector
        val noPriv = "PR:N" in vector
        val noUser = "UI:N" in vector
        return when {
            score >= 9.0 && network && noPriv && noUser -> SignalKind.S1
            score >= 8.0 && network && noPriv -> SignalKind.S1_8
            else -> null
        }
    }
}

/** 같은 제품군·같은 날 공개된 CVE 묶음에서 "인증 우회 + 권한이 필요한 원격 실행"이 함께 있으면 체인으로 본다. */
object ChainRule {
    data class Cve(val id: String, val vector: String, val description: String)

    private val BYPASS = Regex("authentication bypass|bypass authentication|missing authentication", RegexOption.IGNORE_CASE)
    private val EXEC = Regex("remote code execution|command injection|execute arbitrary (code|commands)", RegexOption.IGNORE_CASE)
    private val NEEDS_PRIV = Regex("PR:[LH]")

    fun isChain(sameDay: List<Cve>): Boolean = findChain(sameDay) != null

    /** 체인이면 (인증 우회 CVE, 원격 실행 CVE) 각각 첫 번째 것의 ID를 돌려준다. */
    fun findChain(sameDay: List<Cve>): Pair<String, String>? {
        val bypass = sameDay.firstOrNull { "PR:N" in it.vector && BYPASS.containsMatchIn(it.description) } ?: return null
        val exec = sameDay.firstOrNull { NEEDS_PRIV.containsMatchIn(it.vector) && EXEC.containsMatchIn(it.description) } ?: return null
        return bypass.id to exec.id
    }
}
