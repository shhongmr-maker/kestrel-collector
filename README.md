# 수집기 배치 (공개 저장소 kestrel-collector)

이 폴더는 공개 수집기 저장소에 옮길 파일이다. 공개 저장소에는 다음만 둔다.

```
rules-core/  collector/  gradle/  gradlew  gradle.properties
settings.gradle.kts  build.gradle.kts     ← 이 폴더의 공개 저장소용 파일(앱 제외)
.github/workflows/collect.yml             ← 이 폴더의 파일
```

연구 자료(research/), 설계 문서, 화면 시안은 비공개 저장소(kestrel)에만 둔다.

## 만들기

비공개 저장소(kestrel)에서 `deploy/make-collector-repo.sh <빈 폴더>`를 실행하면 공개 저장소에 올릴 파일이 모인다(앱·연구 자료·문서 제외). 그 폴더를 새 공개 저장소로 푸시한다.

## 비밀 값 (Settings > Environments > `collector` 환경에 저장)

저장소 전체 Secret이 아니라 `collector` 환경에만 둔다. 환경 설정에서 배포 브랜치를 `main`으로 제한한다.

| 이름 | 종류 | 내용 |
|---|---|---|
| `FCM_SERVICE_ACCOUNT` | Secret | Firebase 서비스 계정 키 JSON 파일 내용 전체 |
| `FCM_FIDS` | Secret | 앱 설정 화면이 보여 주는 기기 ID(FID). 기기가 여럿이면 쉼표로 구분. firebase-messaging 25.1.0부터 등록 토큰 대신 FID를 쓴다 |
| `NVD_API_KEY` | Secret (선택) | 있으면 NVD 요청 간격이 짧아진다 |
| `FCM_MODE` | Variable (선택) | `v2`면 FCM v2 RemoteNotification(미리보기). 비우면 v1 고우선순위. **v2에서는 시스템이 알림을 직접 띄워 🔴의 소리 반복·알람 분류가 빠질 수 있다.** 실제 기기 시험 전에는 비워 둔다 |

## 앱 보안 공지 (선택)

Kestrel 앱 자신에게서 취약점이 발견되면 `config/app-advisory.json`을 만들어 커밋한다. 다음 수집부터 feed에 실려, 그보다 낮은 버전의 앱에 "업데이트 필요"가 뜬다. 고친 판이 퍼지면 파일을 지운다.

```json
{"minVersionCode": 3, "message": "0.1.2 이하에서 ○○ 문제가 발견됐다. 0.1.3으로 업데이트한다", "url": "https://github.com/<owner>/kestrel/releases"}
```

## data 브랜치

- `state/state.json`: 소스별 상태, 최근 30일 원자료 캐시, 알린 이벤트
- `public/feed.json`: 앱이 받는 이벤트 목록(공개 정보만)
- `public/push-status.json`: 마지막 푸시 결과(기기 ID는 끝 6자리만)

기록을 쌓지 않고 매 실행 덮어쓴다. 앱은 푸시에 담긴 `feedSha`로 `https://raw.githubusercontent.com/<owner>/kestrel-collector/<feedSha>/public/feed.json`을 받고, 실패하면 `data` 브랜치의 최신 파일을 받는다.

## 알려진 한계

- 푸시가 일시적으로 실패한 알림은 다음 실행에서 다시 보낸다(3일 이내). 기기 ID가 틀렸거나(UNREGISTERED 등) 비밀 값이 없으면 다시 보내지 않는다. 실패는 워크플로 실패(GitHub 메일 알림)와 `push-status.json`으로 드러나고, 내용은 feed에 남으므로 앱을 열면 보인다.
- 테스트 코드는 이 저장소에 없다(외부 기사 원문 사본 포함). 테스트는 비공개 저장소(kestrel)의 CI가 돌린다.
- data 커밋을 강제로 덮어쓰므로, 이전 SHA의 feed는 다음 실행 뒤에는 받을 수 없을 수 있다.
