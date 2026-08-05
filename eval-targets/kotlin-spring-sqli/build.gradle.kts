// Minimal Gradle manifest so stack_detect classifies this as a JVM project.
// Files are not actually built; the manifest's only role is to let
// detect_projects() return a JAVA ProjectKind so the eval picks Kotlin.
plugins {
    id("org.jetbrains.kotlin.jvm") version "2.0.0"
    id("org.springframework.boot") version "3.3.0"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
}
