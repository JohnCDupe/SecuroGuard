plugins {
    `java-library`
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    withSourcesJar()
}

dependencies {
    // Gson is exposed as `api` so downstream consumers (Sentinel) inherit it.
    // Minecraft already bundles a compatible Gson, so the Fabric module uses
    // the game's copy at runtime rather than shading a second one.
    api("com.google.code.gson:gson:${property("gsonVersion")}")

    testImplementation(platform("org.junit:junit-bom:${property("junitVersion")}"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

// Package the project's legal files into the (nested) core jar and its sources jar.
val legalFiles = rootProject.files("LICENSE", "NOTICE")
tasks.named<Jar>("jar") {
    from(legalFiles) { into("META-INF") }
}
tasks.named<Jar>("sourcesJar") {
    from(legalFiles) { into("META-INF") }
}
