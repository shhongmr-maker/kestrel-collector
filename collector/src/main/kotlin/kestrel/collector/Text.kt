package kestrel.collector

/** HTML 조각 정리. Python 시제품(research/shadow/fetch_news.py)의 re.sub·html.unescape와 같게 동작하도록 맞췄다. */
internal object Html {
    private val TAG = Regex("<[^>]+>")
    private val ENTITY = Regex("&(#[0-9]+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);")

    // 뉴스 제목·요약에 실제로 나오는 이름 있는 엔티티. 목록에 없는 이름은 Python처럼 그대로 둔다.
    private val NAMED = mapOf(
        "amp" to "&", "lt" to "<", "gt" to ">", "quot" to "\"", "apos" to "'", "nbsp" to " ",
        "ndash" to "–", "mdash" to "—", "lsquo" to "‘", "rsquo" to "’",
        "ldquo" to "“", "rdquo" to "”", "hellip" to "…", "middot" to "·",
        "bull" to "•", "laquo" to "«", "raquo" to "»", "copy" to "©",
        "reg" to "®", "trade" to "™", "times" to "×", "eacute" to "é",
    )

    fun stripTags(s: String, replacement: String): String = TAG.replace(s, replacement)

    fun unescape(s: String): String = ENTITY.replace(s) { m ->
        val body = m.groupValues[1]
        when {
            body.startsWith("#x") || body.startsWith("#X") -> codePoint(body.substring(2).toLongOrNull(16))
            body.startsWith("#") -> codePoint(body.substring(1).toLongOrNull())
            else -> NAMED[body] ?: m.value
        }
    }

    private fun codePoint(n: Long?): String =
        if (n == null || n == 0L || n > 0x10FFFF || n in 0xD800..0xDFFF) "�" else String(Character.toChars(n.toInt()))
}

/** Python 문자열 자르기(s[:n])와 같게 코드 포인트 단위로 자른다. */
internal fun String.takeCodePoints(n: Int): String {
    if (codePointCount(0, length) <= n) return this
    return substring(0, offsetByCodePoints(0, n))
}

private val CONTROL = Regex("[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]")

/** 외부 문자열을 저장·전달용으로 정리한다: 제어 문자 제거, 앞뒤 공백 제거, [n] 코드 포인트까지. */
internal fun String.clip(n: Int): String = CONTROL.replace(this, "").trim().takeCodePoints(n)

/** 게시글 본문 HTML을 줄 단위 일반 텍스트로 바꾼다. 줄바꿈이 되는 태그는 줄바꿈으로, 표의 칸은 " | "로 바꾼다. */
internal object HtmlText {
    private val SCRIPT = Regex("<(script|style)\\b.*?</\\1>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
    private val BREAK = Regex("<(br|/p|/div|/li|/tr|/h[1-6]|/table)\\b[^>]*>", RegexOption.IGNORE_CASE)
    private val CELL = Regex("</t[dh]>", RegexOption.IGNORE_CASE)
    private val SPACES = Regex("[ \\t\\u00A0]+")
    private val BLANK_LINES = Regex("\\n\\s*\\n+")

    fun of(html: String): String {
        // 원본의 줄바꿈은 공백일 뿐이다. 줄은 태그로만 나눈다
        var t = SCRIPT.replace(html, " ").replace('\r', ' ').replace('\n', ' ')
        t = BREAK.replace(t, "\n")
        t = CELL.replace(t, " | ")
        t = Html.unescape(Html.stripTags(t, ""))
        t = t.lines().joinToString("\n") { SPACES.replace(it, " ").trim().removeSuffix("|").trim() }
        return BLANK_LINES.replace(t, "\n").trim()
    }
}
