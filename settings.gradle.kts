pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        maven("https://maven.fabricmc.net/") { name = "Fabric" }
    }
}

rootProject.name = "securoguard"

include("securoguard-core")
include("securoguard-fabric")
include("securoguard-sentinel")
