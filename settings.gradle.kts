// 공개 수집기 저장소(kestrel-collector)용. 앱(app)과 Android 플러그인은 넣지 않는다.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "kestrel-collector"

include("rules-core")
include("collector")
