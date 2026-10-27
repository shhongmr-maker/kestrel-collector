package kestrel.rules

/**
 * 핵심 제품군(S6) 목록. research/shadow/s6.py와 같은 내용이다.
 *
 * - [textPattern]: 기사 제목이나 CVE 설명에서 이 제품군을 찾는 패턴 (대소문자 구분)
 * - [kevVendor], [kevProduct]: KEV의 vendorProject / product에 대한 패턴 (대소문자 무시). [kevProduct]가 null이면 벤더 전체.
 *   v6: product 칸이 회사명뿐인 항목(예: Microsoft / Microsoft)이 있어 [kevProduct]는 취약점 이름에도 대어 본다
 *
 * 패턴은 느슨하면 크게 틀린다. 예: "PHP"만으로는 WordPress 플러그인의 "PHP Object Injection"까지 잡힌다.
 */
object ProductCatalog {
    enum class Category { EDGE, FILE_TRANSFER, COLLAB, RUNTIME, REMOTE }

    data class Group(
        val name: String,
        val category: Category,
        val textPattern: Regex,
        val kevVendor: Regex,
        val kevProduct: Regex?,
    )

    private fun g(name: String, category: Category, text: String, vendor: String, product: String? = null) = Group(
        name, category, Regex(text),
        Regex(vendor, RegexOption.IGNORE_CASE),
        product?.let { Regex(it, RegexOption.IGNORE_CASE) },
    )

    val groups: List<Group> = listOf(
        g("Fortinet", Category.EDGE, """\bFortinet\b|FortiOS|FortiGate|FortiProxy|FortiWeb|FortiManager|FortiSIEM|FortiSwitch|FortiVoice|FortiClient ?EMS""", "Fortinet"),
        g("PaloAlto", Category.EDGE, "PAN-OS|GlobalProtect|Palo Alto Networks", "Palo Alto"),
        g("Ivanti", Category.EDGE, """\bIvanti\b""", "Ivanti"),
        g("Citrix", Category.EDGE, "NetScaler|Citrix (ADC|Gateway|Bleed)", "Citrix"),
        g("SonicWall", Category.EDGE, "SonicWall|SonicOS", "SonicWall"),
        g("Juniper", Category.EDGE, "Juniper|Junos", "Juniper"),
        g("F5", Category.EDGE, "BIG-IP|F5 Networks", "^F5"),
        g("CheckPoint", Category.EDGE, "Check Point", "Check Point"),
        g("Cisco", Category.EDGE, "Cisco (ASA|Adaptive Security|Firepower|IOS XE|ISE|Identity Services|Secure Firewall|AnyConnect|Secure Client|(Catalyst )?SD-WAN|Secure Email)", "Cisco", "ASA|Firepower|IOS XE|ISE|Secure Firewall|AnyConnect|Identity Services|SD-WAN|Secure Email|Email Gateway"),
        g("Zyxel", Category.EDGE, "Zyxel", "Zyxel"),
        g("Barracuda", Category.EDGE, "Barracuda", "Barracuda"),
        g("MOVEit", Category.FILE_TRANSFER, "MOVEit", "Progress", "MOVEit"),
        g("GoAnywhere", Category.FILE_TRANSFER, "GoAnywhere", "Fortra"),
        g("Cleo", Category.FILE_TRANSFER, """\bCleo (Harmony|VLTrader|LexiCom)""", "Cleo"),
        g("Exchange", Category.COLLAB, "Exchange Server", "Microsoft", "Exchange Server"),
        g("SharePoint", Category.COLLAB, "SharePoint", "Microsoft", "SharePoint"),
        g("Atlassian", Category.COLLAB, "Confluence|Jira|Bitbucket", "Atlassian"),
        g("Zimbra", Category.COLLAB, "Zimbra", "Zimbra|Synacor"),
        g("ApacheCore", Category.RUNTIME, "Apache (HTTP Server|Tomcat|Struts|Log4j|ActiveMQ|OFBiz)", "Apache", "HTTP|Tomcat|Struts|Log4j|ActiveMQ|OFBiz"),
        g("VMware", Category.RUNTIME, "VMware|vCenter|ESXi", "VMware|Broadcom", "VMware|vCenter|ESXi"),
        g("PHPcore", Category.RUNTIME, """^PHP (uses|has|versions?|before|8\.|7\.|warns|ships|issues|patches|fixes|shares|releases)|php-src|\bPHP2Shell\b|\bPHP (engine|interpreter|core)\b""", "^PHP( Group)?$"),
        g("OpenSSH", Category.RUNTIME, "OpenSSH", "OpenBSD|OpenSSH"),
        g("OpenSSL", Category.RUNTIME, "OpenSSL", "OpenSSL"),
        g("WebLogic", Category.RUNTIME, "WebLogic Server(?! Proxy)", "Oracle", "WebLogic"),
        g("NetWeaver", Category.RUNTIME, "NetWeaver", "SAP", "NetWeaver"),
        g("Veeam", Category.RUNTIME, "Veeam", "Veeam"),
        // v6 (docs/10): 6개월 재생에서 KEV·보도가 있었는데 제품군 밖이라 알림이 없던 제품
        g("NodeJS", Category.RUNTIME, """\bNode2Shell\b|^Node\.js\b|^(A|An) (flaw|vulnerability|issue|bug) in Node\.js\b|\bNode\.js (core|runtime|versions? \d|v\d+\.|\d+\.\d+)""", """Node\.?js|OpenJS""", "Node"),
        g("Brotli", Category.RUNTIME, """\bBrotli\b""", "Google", "Brotli"),
        g("OracleEBS", Category.RUNTIME, "E-Business Suite|PeopleSoft", "Oracle", "E-Business Suite|PeopleSoft"),
        g("MikroTik", Category.EDGE, "MikroTik|RouterOS", "MikroTik"),
        g("VeloCloud", Category.EDGE, "VeloCloud", "Arista|VMware|Broadcom", "VeloCloud"),
        g("LoadMaster", Category.EDGE, "LoadMaster", "Progress", "LoadMaster"),
        g("Sophos", Category.EDGE, "Sophos (Firewall|XG|UTM)", "Sophos", "Firewall|XG|UTM"),
        g("WatchGuard", Category.EDGE, "WatchGuard|Fireware", "WatchGuard"),
        g("ServU", Category.FILE_TRANSFER, "Serv-U", "SolarWinds", "Serv-U"),
        g("CrushFTP", Category.FILE_TRANSFER, "CrushFTP", "CrushFTP"),
        g("WingFTP", Category.FILE_TRANSFER, "Wing FTP", "Wing FTP"),
        g("Collabora", Category.COLLAB, """\bCollabora\b|Nextcloud|ownCloud""", "Collabora|Nextcloud|ownCloud"),
        g("Roundcube", Category.COLLAB, "Roundcube", "Roundcube"),
        g("ScreenConnect", Category.REMOTE, "ScreenConnect", "ConnectWise", "ScreenConnect"),
        g("BeyondTrust", Category.REMOTE, "BeyondTrust", "BeyondTrust"),
        g("SimpleHelp", Category.REMOTE, "SimpleHelp", "SimpleHelp"),
        g("NCentral", Category.REMOTE, "N-central", "N-able", "N-central"),
    )

    val names: Set<String> = groups.map { it.name }.toSet()

    /**
     * KISA 공지 제목 맨 앞의 제품명("PHP 신규 취약점 …", "Ivanti 제품 보안 주의 권고").
     * 한 회사에 핵심 제품군이 하나뿐인 경우만 둔다(Microsoft·Oracle·SAP·Cisco·Apache 제외). engine.py의 KISA_LEAD와 같다.
     */
    private val kisaLead: List<Pair<String, Regex>> = listOf(
        "Fortinet" to "Fortinet|FortiOS|FortiGate|포티넷", "PaloAlto" to "Palo ?Alto|PAN-OS|팔로알토", "Ivanti" to "Ivanti|이반티",
        "Citrix" to "Citrix|NetScaler|시트릭스", "SonicWall" to "SonicWall|소닉월", "Juniper" to "Juniper|주니퍼", "F5" to "F5|BIG-IP",
        "CheckPoint" to "Check ?Point|체크포인트", "Zyxel" to "Zyxel|자이젤", "Barracuda" to "Barracuda|바라쿠다", "MOVEit" to "MOVEit",
        "GoAnywhere" to "GoAnywhere", "Atlassian" to "Atlassian|Confluence|Jira|아틀라시안", "Zimbra" to "Zimbra|짐브라",
        "VMware" to "VMware", "PHPcore" to "PHP", "OpenSSH" to "OpenSSH", "OpenSSL" to "OpenSSL", "Veeam" to "Veeam",
        "NodeJS" to """Node\.?js|노드""", "MikroTik" to "MikroTik|마이크로틱", "Sophos" to "Sophos|소포스", "WatchGuard" to "WatchGuard|워치가드",
        "CrushFTP" to "CrushFTP", "Roundcube" to "Roundcube", "BeyondTrust" to "BeyondTrust", "ScreenConnect" to "ConnectWise|ScreenConnect",
    ).map { (g, rx) -> g to Regex("""^\(?($rx)(?![A-Za-z0-9])""") }

    /** KISA 제목의 제품군: 일반 정규식이 먼저, 안 맞으면 맨 앞 제품명. */
    fun groupOfKisaTitle(title: String): String? =
        groupOfText(title) ?: kisaLead.firstOrNull { it.second.containsMatchIn(title) }?.first

    /** 기사 제목이나 CVE 설명에서 처음 맞는 제품군 이름. 목록 순서가 우선순위다. */
    fun groupOfText(text: String): String? = groups.firstOrNull { it.textPattern.containsMatchIn(text) }?.name

    /** KEV 항목의 제품군 이름. [name]은 KEV의 취약점 이름(vulnerabilityName). */
    fun groupOfKev(vendorProject: String, product: String, name: String = ""): String? = groups.firstOrNull {
        it.kevVendor.containsMatchIn(vendorProject) &&
            (it.kevProduct == null || it.kevProduct.containsMatchIn(product) || it.kevProduct.containsMatchIn(name))
    }?.name
}
