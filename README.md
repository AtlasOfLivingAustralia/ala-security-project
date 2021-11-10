# ala-ws-security-plugin
Web service authentication and authorization.

## Status
[![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin)

This plugin provides authentication and authorization for Atlas web services written in Grails.
It supports [JSON Web Tokens](https://datatracker.ietf.org/doc/html/rfc7519) based authentication and authorization.

It also supports the deprecated `apiKey` for api keys sources from the [apikey](https://github.com/atlasoflivingaustralia/apikey) app. 
used for internal-app to internal-app. These api keys are to be phased
out in favour of JWTs which can be used for internal and external web service calls.

## Usage

To use this plugin, you will need to include the following dependency in `build.gradle`

```
compile "org.grails.plugins:ala-ws-security-plugin:3.0.0-SNAPSHOT"
```

In addition, you will need to add the following bean definition to `grails-app/conf/spring/resources.groovy`.

```groovy
package spring

import au.ala.org.ws.security.AlaWebServiceAuthFilter

// Place your Spring DSL code here
beans = {
    authFilter(AlaAuthFilter)
}
```

## Spring security

When used in an application which is also using Spring Security, web service endpoints should be excluded using
a bean that extends WebSecurityConfigurerAdapter.

```groovy
@Configuration
@EnableWebSecurity
@Order(1) // required to override the default Oauth2 spring configuration
class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(
                        "/",
                        "/css/**",
                        "/assets/**",
                        "/messages/**",
                        "/i18n/**",
                        "/static/**",
                        "/images/**",
                        "/js/**",
                        "/ws/**"
                ).permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .oauth2Login()
                .and()
                .logout().invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID").permitAll()
                .and().csrf().disable();
    }
}

```

this bean also needs to be referenced in `grails-app/conf/spring/resources.groovy`.

```groovy
package spring

import au.ala.org.ws.security.AlaWebServiceAuthFilter

// Place your Spring DSL code here
beans = {
    authFilter(AlaAuthFilter)
    securityConfig(SecurityConfig)
}
```

### Demo application

TBA.....

## Calling services with JSON Web Tokens

JWTs can be generated using the service....

## Calling services with Legacy API key

From the client side, set the ```apiKey``` request _header_  on all secured service requests to a valid API Key (registered in the API Key service).

On the server side, annotate protected controllers (either the class or individual methods) with the ```@RequireApiKey``` annotation.

## External configuration properties

### Mandatory
- ```security.apikey.check.serviceUrl``` - URL of the API Key service endpoint, up to and including the key parameter name. E.g. https://auth.ala.org.au/apikey/ws/check?apikey=

### Optional
- ```security.apikey.ip.whitelist``` - comma separated list of IP Addresses that are exempt from the API key security check.
- ```security.apikey.header.override ``` - override the default request header name (apiKey) to use a different name.

## Changelog
- **Version 3.0**
  - JSON Web Token support
- **Version 2.0**
  - Grails 3 version
- **Version 1.0** (2/7/2015)
  - Initial release.
  - Includes a grails filter and a ```RequireApiKey``` annotation for securing web service calls via the ALA API Key infrastructure.
