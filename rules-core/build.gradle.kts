import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    `java-test-fixtures`
}

repositories {
    mavenCentral()
}

// 의존성 버전을 잠금 파일(gradle.lockfile)로 고정한다. 바꿀 때: ./gradlew dependencies --write-locks
dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    testImplementation(kotlin("test"))
    // research/의 원자료 JSON을 읽는 테스트 픽스처(ResearchData)에서만 쓴다. rules-core 본체는 외부 의존성이 없다.
    testFixturesImplementation("org.json:json:20260814")
}

java {
    // Android(minSdk 26+)와 GitHub Actions 러너 양쪽에서 쓰기 위해 바이트코드는 17로 맞춘다
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
        showStandardStreams = false
    }
}
