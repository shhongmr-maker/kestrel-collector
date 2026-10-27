package kestrel.collector

import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.Charset
import java.time.Duration
import java.util.zip.GZIPInputStream

data class HttpResult(val status: Int, val body: String, val headers: Map<String, String>) {
    fun header(name: String): String? = headers[name.lowercase()]
}

/** 소스 요청. 테스트에서는 고정 응답으로 바꿔 끼운다. */
fun interface Fetcher {
    fun get(url: String, headers: Map<String, String>): HttpResult
}

/** POST 요청(FCM 토큰 발급·발송). */
fun interface Poster {
    fun post(url: String, headers: Map<String, String>, body: String): HttpResult
}

/** 응답 상태가 실패이거나 재시도를 다 써도 연결되지 않을 때. */
class SourceFetchException(val source: String, message: String, cause: Throwable? = null) :
    Exception("$source: $message", cause)

/**
 * JDK HttpClient로 요청한다. 연결 오류·429·5xx는 2, 4, 8초 간격으로 재시도한다(Retry-After가 있으면 그 값, 최대 60초).
 * gzip으로 받아 풀고, 문자 집합이 없으면 UTF-8로 읽는다.
 * 응답은 [maxBytes]까지만 읽는다(압축을 푼 크기 기준). 넘으면 재시도하지 않고 [SourceFetchException]을 던진다(메모리 고갈·gzip 폭탄 방지).
 */
class JdkFetcher(
    private val userAgent: String,
    private val timeout: Duration = Duration.ofSeconds(60),
    private val retries: Int = 3,
    private val sleep: (Duration) -> Unit = { Thread.sleep(it.toMillis()) },
    /** KEV 전체 약 1.8MB, NVD 2,000건 한 쪽 약 7MB(2026-10-26 기준)보다 넉넉하게 둔다. */
    private val maxBytes: Long = 64L * 1024 * 1024,
) : Fetcher, Poster {
    private val client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(20))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

    override fun get(url: String, headers: Map<String, String>): HttpResult = withRetry(retryOnIo = true) { once(url, headers, null) }

    /**
     * POST(FCM 발송)는 연결 오류·시간 초과에서 재시도하지 않는다. 서버가 이미 받았을 수 있어 같은 알림이 두 번 울리기 때문이다.
     * 429·5xx는 서버가 처리하지 않았다는 뜻이라 재시도한다.
     */
    override fun post(url: String, headers: Map<String, String>, body: String): HttpResult = withRetry(retryOnIo = false) { once(url, headers, body) }

    private fun withRetry(retryOnIo: Boolean, call: () -> HttpResult): HttpResult {
        var attempt = 0
        while (true) {
            val wait = try {
                val result = call()
                if (result.status != 429 && result.status < 500) return result
                if (attempt >= retries) return result
                result.header("retry-after")?.trim()?.toLongOrNull()?.let { Duration.ofSeconds(it.coerceIn(1, 60)) } ?: backoff(attempt)
            } catch (e: IOException) {
                if (!retryOnIo || attempt >= retries) throw e
                backoff(attempt)
            }
            sleep(wait)
            attempt++
        }
    }

    private fun backoff(attempt: Int): Duration = Duration.ofSeconds(2L shl attempt)

    private fun once(url: String, headers: Map<String, String>, body: String?): HttpResult {
        val req = HttpRequest.newBuilder(URI.create(url))
            .timeout(timeout)
            .header("User-Agent", userAgent)
            .header("Accept-Encoding", "gzip")
            .apply { headers.forEach { (k, v) -> header(k, v) } }
            .apply { if (body == null) GET() else POST(HttpRequest.BodyPublishers.ofString(body)) }
            .build()
        val res = client.send(req, HttpResponse.BodyHandlers.ofInputStream())
        val h = res.headers().map().entries.associate { (k, v) -> k.lowercase() to v.joinToString(", ") }
        val bytes = res.body().use { raw ->
            val stream = if (h["content-encoding"]?.contains("gzip", ignoreCase = true) == true) GZIPInputStream(raw) else raw
            readLimited(stream, url)
        }
        val charset = h["content-type"]?.let { CHARSET.find(it)?.groupValues?.get(1) }
            ?.let { runCatching { Charset.forName(it.trim('"')) }.getOrNull() } ?: Charsets.UTF_8
        return HttpResult(res.statusCode(), String(bytes, charset), h)
    }

    private fun readLimited(input: java.io.InputStream, url: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > maxBytes) throw SourceFetchException(URI.create(url).host ?: url, "응답이 ${maxBytes / (1024 * 1024)}MB를 넘음")
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private companion object {
        val CHARSET = Regex("charset=([^;\\s]+)", RegexOption.IGNORE_CASE)
    }
}
