package kestrel.collector

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 공개 저장소 data 브랜치에 올리는 파일의 보호. 키는 Actions 비밀 값 KESTREL_DATA_KEY(EC P-256 개인 키, PKCS#8 DER의 base64) 하나다.
 * - feed 서명: feed.json 바이트를 SHA256withECDSA로 서명해 feed.json.sig(base64)로 둔다. 앱은 공개 키(앱에 고정)로 확인한다
 * - state 암호화: state.json을 AES-256-GCM으로 암호화한다. 키는 개인 키에서 유도한다(SHA-256). 원자료(기사·공지 본문)가 공개되지 않게 한다
 * 키가 없으면 둘 다 하지 않는다(이전과 같은 동작).
 */
class DataKey(private val privateKey: PrivateKey) {
    companion object {
        const val ENV = "KESTREL_DATA_KEY"
        /** 암호화한 state의 머리말. 이게 없으면 평문 state다 */
        const val STATE_PREFIX = "KSTATE1:"
        private val AAD = "kestrel-state".toByteArray()

        fun parse(b64: String): DataKey =
            DataKey(KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64.trim()))))

        fun fromEnv(): DataKey? = System.getenv(ENV)?.takeIf { it.isNotBlank() }?.let(::parse)

        /** 서명 확인(감시 워크플로·테스트용). [publicB64]는 X.509 SubjectPublicKeyInfo DER의 base64 */
        fun verify(publicB64: String, data: ByteArray, sigB64: String): Boolean = runCatching {
            val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicB64.trim())))
            Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(data); verify(Base64.getDecoder().decode(sigB64.trim())) }
        }.getOrDefault(false)

        /** 파일에서 읽은 state 글: 암호화돼 있으면 풀고, 평문이면 그대로(키를 처음 넣은 실행에서 옮겨 간다) */
        fun readState(text: String, key: DataKey?): String =
            if (text.startsWith(STATE_PREFIX)) (key ?: error("state가 암호화돼 있는데 $ENV 가 없다")).decrypt(text) else text

        fun writeState(text: String, key: DataKey?): String = key?.encrypt(text) ?: text
    }

    private val stateKey = SecretKeySpec(MessageDigest.getInstance("SHA-256").digest("kestrel-state-v1".toByteArray() + privateKey.encoded), "AES")

    fun sign(data: ByteArray): String =
        Base64.getEncoder().encodeToString(Signature.getInstance("SHA256withECDSA").run { initSign(privateKey); update(data); sign() })

    fun encrypt(text: String): String {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, stateKey, GCMParameterSpec(128, iv)); updateAAD(AAD) }
        return STATE_PREFIX + Base64.getEncoder().encodeToString(iv + c.doFinal(text.toByteArray()))
    }

    fun decrypt(text: String): String {
        val raw = Base64.getDecoder().decode(text.removePrefix(STATE_PREFIX).trim())
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, stateKey, GCMParameterSpec(128, raw, 0, 12)); updateAAD(AAD) }
        return String(c.doFinal(raw, 12, raw.size - 12))
    }
}
