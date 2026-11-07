package kestrel.rules

/**
 * CVE 하나로 묶인 위협의 제품 이름(제목 앞부분). 수집기가 만들고, 앱은 [isWordPressAddon]으로 WordPress 플러그인·테마를 알아본다.
 * - KEV: "WordPress WordPress Core" → "WordPress Core", "Apple Multiple Products" → "Apple 여러 제품"
 * - NVD: 제조사를 붙이고("E8450" → "Linksys E8450"), WordPress 플러그인·테마는 "WordPress 플러그인 …"으로 쓴다
 *   (CNA가 적는 플러그인 제조사 이름은 대개 개발자 계정이라 뜻이 없다)
 */
object ProductNames {
    const val WP_PLUGIN = "WordPress 플러그인 "
    const val WP_THEME = "WordPress 테마 "

    private val WP = Regex("""\b(plugin|theme)s? for WordPress\b""", RegexOption.IGNORE_CASE)
    private val NO_VENDOR = setOf("n/a", "na", "unknown", "-", "none")

    fun kev(vendor: String, product: String): String {
        val v = vendor.trim()
        val p = product.trim()
        return when {
            p.equals("Multiple Products", ignoreCase = true) -> if (v.isEmpty()) "여러 제품" else "$v 여러 제품"
            v.isEmpty() -> p
            p.isEmpty() -> v
            p.lowercase().startsWith(v.lowercase()) -> p
            else -> "$v $p"
        }
    }

    /** NVD 설명에 "plugin for WordPress"·"theme for WordPress"가 있으면 "plugin"·"theme" */
    fun wordPressAddon(description: String): String? = WP.find(description)?.groupValues?.get(1)?.lowercase()

    /** 앱: 수집기가 붙인 제목 앞부분으로 WordPress 플러그인·테마 취약점인지 본다 */
    fun isWordPressAddon(title: String): Boolean = WP_PLUGIN in title || WP_THEME in title

    /**
     * NVD 영향 범위의 제조사·제품으로 이름을 만든다. [shortProduct]는 긴 제품명을 줄이는 함수(수집기의 규칙).
     * CPE 표기(소문자·밑줄, 예: linksys / e8450_firmware)보다 CNA 표기(Linksys / E8450)를 먼저 쓴다.
     */
    fun nvd(c: NvdCve, shortProduct: (String) -> String): String {
        val ranges = c.affected.filter { it.product.isNotBlank() }
        val r = ranges.firstOrNull { cnaStyle(it.product) || cnaStyle(it.vendor) } ?: ranges.firstOrNull() ?: return ""
        val product = shortProduct(pretty(r.product))
        if (product.isEmpty()) return ""
        when (wordPressAddon(c.description)) {
            "plugin" -> return WP_PLUGIN + product
            "theme" -> return WP_THEME + product
        }
        val vendor = pretty(r.vendor).takeUnless { it.lowercase() in NO_VENDOR }.orEmpty()
        return if (vendor.isEmpty() || product.lowercase().startsWith(vendor.lowercase())) product else "$vendor $product"
    }

    private fun cnaStyle(s: String) = s.any { it.isUpperCase() } || ' ' in s.trim()

    /** CPE 표기면 밑줄을 띄어쓰기로, 모두 소문자면 첫 글자만 대문자로 */
    private fun pretty(s: String): String {
        val t = s.trim().replace('_', ' ')
        return if (t.isNotEmpty() && t == t.lowercase() && t.first().isLetter()) t.replaceFirstChar { it.uppercase() } else t
    }
}
