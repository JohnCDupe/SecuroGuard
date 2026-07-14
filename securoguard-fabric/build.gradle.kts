plugins {
    id("fabric-loom") version "1.17.14"
}

// Single-sourced from the root `version` in gradle.properties. The full version —
// including any prerelease such as "-SNAPSHOT" or "-rc.1" — is preserved, with the
// Minecraft build appended as SemVer build metadata after "+". A development build
// must never masquerade as a stable release. Examples:
//   0.1.0-SNAPSHOT -> 0.1.0-SNAPSHOT+mc1.21.11
//   0.1.0-rc.1     -> 0.1.0-rc.1+mc1.21.11
//   0.1.0          -> 0.1.0+mc1.21.11
// Bumping the release version is therefore a one-line edit to gradle.properties.
version = "${property("version")}+mc${property("minecraftVersion")}"
base.archivesName = property("modId") as String

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    maven("https://maven.fabricmc.net/") { name = "Fabric" }
    // Mod Menu (optional integration). Isolated to this module.
    maven("https://maven.terraformersmc.com/releases/") { name = "TerraformersMC" }
}

dependencies {
    minecraft("com.mojang:minecraft:${property("minecraftVersion")}")
    mappings("net.fabricmc:yarn:${property("yarnMappings")}:v2")
    modImplementation("net.fabricmc:fabric-loader:${property("loaderVersion")}")
    modImplementation("net.fabricmc.fabric-api:fabric-api:${property("fabricApiVersion")}")

    // Mod Menu provides the config-screen entry point. Optional at runtime.
    modImplementation("com.terraformersmc:modmenu:${property("modmenuVersion")}")

    // The loader-neutral security engine. Bundled into the mod jar with `include`
    // so it ships alongside the mod without a separate install step.
    implementation(project(":securoguard-core"))
    include(project(":securoguard-core"))

    testImplementation(platform("org.junit:junit-bom:${property("junitVersion")}"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

val modProps = mapOf(
    "version" to project.version,
    "minecraftVersion" to project.property("minecraftVersion"),
    "loaderVersion" to project.property("loaderVersion"),
)

tasks.processResources {
    inputs.properties(modProps)
    filesMatching("fabric.mod.json") {
        expand(modProps)
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
}

// Package the project's legal files into the mod jar (remapJar remaps this jar, so
// the files are carried into the production artifact) and the sources jar.
val legalFiles = rootProject.files("LICENSE", "NOTICE")
tasks.named<Jar>("jar") {
    from(legalFiles) { into("META-INF") }
}
tasks.named<Jar>("sourcesJar") {
    from(legalFiles) { into("META-INF") }
}
