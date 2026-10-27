package kestrel.collector

/** 파서 결과. 형식이 어긋난 항목 하나 때문에 전체를 버리지 않도록, 그런 항목은 건너뛰고 [skipped]에 센다. */
data class Parsed<T>(val items: List<T>, val skipped: Int = 0)

/** 항목과 원문 링크. rules-core 입력에는 링크가 없으므로 수집기에서 따로 들고 다닌다. */
data class Linked<T>(val value: T, val url: String)

/**
 * 페이지로 나뉜 응답(NVD API, Blogger 피드)의 한 페이지.
 * [nextOffset]은 다음 요청의 시작 위치(0부터)이고, [total]보다 작으면 더 받아야 한다.
 */
data class Page<T>(val items: List<T>, val skipped: Int, val total: Int, val nextOffset: Int) {
    val hasMore: Boolean get() = nextOffset < total
}

/** 응답 전체 구조가 예상과 다를 때. 소스가 형식을 바꿨거나 차단·오류 페이지를 돌려준 경우다. 소스 상태에 기록할 대상. */
class SourceFormatException(val source: String, message: String, cause: Throwable? = null) :
    Exception("$source: $message", cause)

/** 항목 하나를 바꾸다 실패하면 null. 실패 원인은 버린다(건수만 센다). */
internal inline fun <T> orSkip(block: () -> T): T? = try {
    block()
} catch (e: RuntimeException) {
    null
}

internal fun <T> List<T?>.toParsed(): Parsed<T> = Parsed(filterNotNull(), count { it == null })
