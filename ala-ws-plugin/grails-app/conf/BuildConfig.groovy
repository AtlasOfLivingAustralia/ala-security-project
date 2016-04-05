grails.project.class.dir = "target/classes"
grails.project.test.class.dir = "target/test-classes"
grails.project.test.reports.dir = "target/test-reports"

grails.project.fork = [
    // configure settings for compilation JVM, note that if you alter the Groovy version forked compilation is required
    //  compile: [maxMemory: 256, minMemory: 64, debug: false, maxPerm: 256, daemon:true],

    // configure settings for the test-app JVM, uses the daemon by default
    test: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, daemon:true],
    // configure settings for the run-app JVM
    run: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, forkReserve:false],
    // configure settings for the run-war JVM
    war: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, forkReserve:false],
    // configure settings for the Console UI JVM
    console: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256]
]

grails.project.dependency.resolver = "maven" // or ivy
grails.project.dependency.resolution = {
    // inherit Grails' default dependencies
    inherits("global") {
    }
    log "warn" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    repositories {
        mavenLocal()
        mavenRepo("http://nexus.ala.org.au/content/groups/public/") {
            updatePolicy 'always'
        }
    }
    management {
        dependency "org.apache.httpcomponents:httpmime:4.3.3"
        dependency "org.apache.httpcomponents:httpclient:4.3.3"
    }
    dependencies {
        compile "org.apache.httpcomponents:httpmime:4.3.3"

        test ("io.ratpack:ratpack-core:1.2.0") {
            excludes "io.ratpack:ratpack-guice:1.2.0"
        }
        test "io.ratpack:ratpack-test:1.2.0"
        test ("io.ratpack:ratpack-groovy:1.2.0") {
            excludes "io.ratpack:ratpack-guice:1.2.0"
        }
        test "io.ratpack:ratpack-groovy-test:1.2.0"
    }

    plugins {
        build(":release:3.1.2") {
            excludes "httpclient"
        }

        compile "org.grails.plugins:rest:0.8"

        runtime(":ala-auth:1.3.1") {
            excludes "commons-httpclient"
        }
    }
}
