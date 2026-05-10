plugins {
    kotlin("jvm") version "2.0.20"
    application
}

application {
    mainClass.set("example.AppKt")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-core:2.3.12")
    implementation("io.ktor:ktor-server-netty:2.3.12")
    implementation("org.xerial:sqlite-jdbc:3.46.0.0")
}
