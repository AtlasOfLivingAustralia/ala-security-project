# ala-security-libs
Java libraries and Grails plugins for authentication and authorization with backwards compatibility to previous
ALA plugins

Usage
-----

The current version of these libraries is: `6.0.3`.

To ensure that various plugins and libraries and self-consistent, a project should use the same version for
each of the plugins and libraries that it consumes, eg for a Grails project:

`gradle.properties`:
```gradle.properties
alaSecurityLibsVersion=6.0.3
```

`build.gradle`:
```build.gradle
dependencies {
  implementation "org.grails.plugins:ala-auth-plugin:$alaSecurityLibsVersion"
  implementation "org.grails.plugins:ala-ws-plugin:$alaSecurityLibsVersion"
  implementation "org.grails.plugins:ala-ws-security-plugin:$alaSecurityLibsVersion"
}
```

Components
----------

This project contains all of the following previously separate ALA Grails plugins and libs:

- [ala-auth-plugin](ala-auth) - For interactively authenticating users
- [ala-ws-plugin](ala-ws-plugin) - For adding authenticated tokens to outgoing web service requests
- [ala-ws-security-plugin](ala-ws-security-plugin) - For adding access token authentication for web services
- [userdetails-service-client](userdetails-service-client) - For contacting userdetails web services

In addition there is support for Spring Boot apps using the same underlying libraries and code in:

- [ala-ws-spring-security](ala-ws-spring-security)


