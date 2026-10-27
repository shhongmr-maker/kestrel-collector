import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    application
}

application {
    mainClass.set("kestrel.collector.MainKt")
    // 러너의 로캘과 관계없이 한글 로그가 깨지지 않게 한다
    applicationDefaultJvmArgs = listOf("-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8")
}

// ./gradlew :collector:run --args="… --state state/state.json …"의 상대 경로는 저장소 루트 기준이다.
// 기본값(collector/ 폴더)이면 워크플로가 이전 state를 찾지 못해 매번 첫 실행(알림 없음)이 된다
tasks.named<JavaExec>("run") {
    workingDir = rootProject.projectDir
}

repositories {
    mavenCentral()
}

// 의존성 버전을 잠금 파일(gradle.lockfile)로 고정한다. 바꿀 때: ./gradlew dependencies --write-locks
dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation(project(":rules-core"))
    // 수집기는 GitHub Actions 러너에서만 돈다. JSON은 org.json, XML은 JDK 기본 파서를 쓴다.
    implementation("org.json:json:20260814")
    testImplementation(kotlin("test"))
    testImplementation(testFixtures(project(":rules-core")))
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

tasks.test {
    useJUnitPlatform()
    systemProperty("kestrel.research", rootProject.file("research").absolutePath)
    testLogging {
        events("failed")
    }
}
