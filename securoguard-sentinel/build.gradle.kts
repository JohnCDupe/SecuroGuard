plugins {
    application
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

dependencies {
    implementation(project(":securoguard-core"))

    testImplementation(platform("org.junit:junit-bom:${property("junitVersion")}"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    applicationName = "securoguard"
    mainClass = "com.securoguard.sentinel.SentinelMain"
}

// Include the project's legal files at the root of the Sentinel ZIP/TAR distributions.
distributions {
    named("main") {
        contents {
            from(rootProject.files("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"))
        }
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
