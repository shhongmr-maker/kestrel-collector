package kestrel.collector

import java.time.LocalDate

/**
 * 푸시가 일시적인 이유로 실패한 알림을 "알린 것" 기록에서 빼, 다음 실행이 다시 보내게 한다.
 *
 * 다시 보내지 않는 경우:
 * - 한 기기라도 받았으면(성공)
 * - 기기 ID가 틀렸거나 등록이 풀린 경우(UNREGISTERED 등): 다시 보내도 같다. 앱이 기기 ID 변경을 알린다
 * - 비밀 값이 아직 없는 경우: 설정 전에 쌓인 알림이 설정 직후 한꺼번에 나가지 않게 한다
 * - 알림 날짜가 [maxAgeDays]일보다 오래된 경우
 */
object Requeue {
    const val NO_SECRETS = "FCM_SERVICE_ACCOUNT 또는 FCM_FIDS가 없음"
    private val PERMANENT = Regex("UNREGISTERED|INVALID_ARGUMENT|SENDER_ID_MISMATCH|NOT_FOUND")

    data class Outcome(val state: CollectorState, val requeued: List<String>)

    fun apply(
        state: CollectorState,
        alerts: List<FeedEvent>,
        results: List<FcmSender.Result>,
        globalError: String?,
        today: LocalDate,
        maxAgeDays: Long = 3,
    ): Outcome {
        if (globalError == NO_SECRETS) return Outcome(state, emptyList())
        val retry = alerts.filter { a ->
            val mine = results.filter { it.eventId == a.id }
            val delivered = mine.any { it.ok }
            val permanent = mine.isNotEmpty() && mine.all { !it.ok && PERMANENT.containsMatchIn(it.detail) }
            // 추가 보도는 소식 알림이라 다시 보내지 않는다(다음 기사가 오면 그때 새로 알린다)
            !a.isFollowUp && !delivered && !permanent && a.date >= today.minusDays(maxAgeDays)
        }
        if (retry.isEmpty()) return Outcome(state, emptyList())
        val keep = state.notified.filterNot { n ->
            retry.any { a -> n.date == a.date && n.clusterKey == a.clusterKey && n.level == a.level && n.trigger == a.trigger }
        }
        return Outcome(state.copy(notified = keep), retry.map { it.id })
    }
}
