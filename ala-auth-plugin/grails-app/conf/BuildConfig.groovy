grails.servlet.version = "3.0"
//grails.project.class.dir = "target/classes"
//grails.project.test.class.dir = "target/test-classes"
//grails.project.test.reports.dir = "target/test-reports"
grails.project.work.dir = "target"
grails.project.target.level = 1.7
grails.project.source.level = 1.7

grails.project.dependency.resolver = "maven" // or ivy
grails.project.dependency.resolution = {
    //legacyResolve true // if using Grails > 2.2
    // inherit Grails' default dependencies
    inherits("global") {
        // uncomment to disable ehcache
        // excludes 'ehcache'
    }
    log "warn" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    repositories {
        mavenLocal()
        mavenRepo ("http://nexus.ala.org.au/content/groups/public/") {
            updatePolicy 'always'
        }
    }
    dependencies {
        // specify dependencies here under either 'build', 'compile', 'runtime', 'test' or 'provided' scopes eg.
        // runtime 'mysql:mysql-connector-java:5.1.18'
        compile ('au.org.ala:ala-cas-client:2.4-SNAPSHOT')
        compile ('au.org.ala:userdetails-service-client:1.4.0-SNAPSHOT')

        test ('com.squareup.retrofit2:retrofit-mock:2.4.0')
    }

    plugins {
        compile ':webxml:1.4.1'
        compile(":tomcat:7.0.70") {
            export = false
        }
        runtime(":release:3.1.2") {
            export = false
        }
//        compile ":rest:0.8"
    }
}

