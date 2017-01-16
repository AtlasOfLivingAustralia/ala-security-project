import org.gradle.api.JavaVersion.VERSION_1_7
import org.gradle.api.NamedDomainObjectContainer
import org.gradle.api.artifacts.Configuration
import org.gradle.api.internal.artifacts.configurations.Configurations
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.tasks.SourceSetContainer
import org.gradle.api.tasks.javadoc.Javadoc
import org.gradle.jvm.tasks.Jar

// TODO Integration test

plugins {
    java
    `maven-publish`
}

group = "au.org.ala"
val versionString = "1.0.0-SNAPSHOT"
version = versionString

configure<JavaPluginConvention> {
    sourceCompatibility = VERSION_1_7
    targetCompatibility = VERSION_1_7
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {

    compileOnly(group="org.projectlombok", name="lombok", version="1.16.12")

    compile(group="com.squareup.retrofit2", name="retrofit", version="2.1.0")
    compile(group="com.squareup.retrofit2", name="converter-moshi", version="2.1.0")
    compile(group="com.squareup.moshi", name="moshi", version="1.3.1")
    compile(group="com.squareup.moshi", name="moshi-adapters", version="1.3.1")

    testCompile(group="com.google.guava", name="guava", version="20.0")
    testCompile(group="junit", name="junit", version="4.11")
    testCompile(group="com.squareup.okhttp3", name="logging-interceptor", version="3.3.1")
    testCompile(group="com.squareup.okhttp3", name="mockwebserver", version="3.0.1")
    testCompile(group="org.assertj", name="assertj-core", version="3.6.1")
}

val sourceSets = properties["sourceSets"] as SourceSetContainer

val sourcesJar = task<Jar>("sourcesJar") {
    dependsOn("classes")
    classifier = "sources"
    from(sourceSets.getByName("main").allSource)
}

val javaDocTask = tasks.getByName("javadoc") as Javadoc

val javadocJar = task<Jar>("javadocJar") {
    dependsOn(javaDocTask)
    classifier = "javadoc"
    from(javaDocTask.destinationDir)
}

configure<PublishingExtension> {
    repositories {
        maven {
            name = "Nexus"
            setUrl("http://nexus.ala.org.au/content/repositories/${if (versionString.endsWith("-SNAPSHOT")) "snapshots" else "releases"}")
            credentials {
                username = System.getenv("TRAVIS_DEPLOY_USERNAME")
                password = System.getenv("TRAVIS_DEPLOY_PASSWORD")
            }
        }
    }
    publications {
        create("mavenJava", MavenPublication::class.java) {
            it.from(components.getByName("java"))

            it.artifact(sourcesJar) {
                classifier = "sources"
            }

            it.artifact(javadocJar) {
                classifier = "javadoc"
            }
        }
    }
}
