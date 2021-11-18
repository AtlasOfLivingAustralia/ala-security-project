# ala-ws-security-plugin
Web service authentication and authorization.

## Status
[![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin)

This plugin provides authentication and authorization for Atlas web services written in Grails.

For existing applications, it requires a switch from CAS based authentication to Spring Security with OAuth 2 support.

It supports [JSON Web Tokens](https://datatracker.ietf.org/doc/html/rfc7519) based authentication and authorization for web services.

It maintains support for the deprecated `apiKey` for api keys which are sourced from and validated by 
the [apikey](https://github.com/atlasoflivingaustralia/apikey) application. These are currently only 
used for internal-app to internal-app in the Atlas. These api keys are to be phased
out in favour of JWTs which can be used for internal and external web service calls. JWTs are associated 
with a user and a set roles.

## Usage

To use this plugin, you will need remove dependencies on `ala-auth` plugin and the related CAS configuration from
`application.yml` and `application.groovy`. 

The following dependencies in `build.gradle` are required:

```
compile "org.grails.plugins:ala-ws-security-plugin:3.0.0-SNAPSHOT"
compile "org.springframework.boot:spring-boot-starter-oauth2-client"
```

By default, all URLs will go through OAuth Spring Security Filters which is not desirable for public HTML pages.
Also, this is not desirable for web services as a call that fails authentication/authorization will be routed
to a HTML OAuth login page.

To override the default catch-all behaviour, applications will need to define
a `SecurityConfig` bean that extends WebSecurityConfigurerAdapter in the `grails-app/init` directory. Here is an example"

```groovy
@Configuration
@EnableWebSecurity
@Order(1) // required to override the default Oauth2 spring configuration
class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  AlaOAuth2UserService alaOAuth2UserService

  @Value('${spring.security.logoutUrl:"http://dev.ala.org.au:8080"}')
  String logoutUrl

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
            .antMatchers(
                    "/",
                    "/public/**",
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
            .successHandler(new SavedRequestAwareAuthenticationSuccessHandler())
            .userInfoEndpoint()
            .oidcUserService(alaOAuth2UserService)
            .and()
            .and()
            .logout()
            .logoutUrl(logoutUrl)
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .deleteCookies("JSESSIONID").permitAll()
            .and().csrf().disable()
  }
}
```

The following bean definitions are required in `grails-app/conf/spring/resources.groovy`.

```groovy
beans = {
  alaOAuth2UserService(AlaOAuth2UserService)   // customized UserService - user roles added to OidcUser.authorities 
  alaWebServiceAuthFilter(AlaWebServiceAuthFilter) // filter that checks JWTs & Legacy API keys
  securityConfig(SecurityConfig) // custom security config for your app
}
```

### External configuration

When upgrading to this plugin, existing CAS configuration can be removed.
The following configuration is required.

```yaml
spring: 
  security:
    spring.security.logoutUrl: http://dev.ala.org.au:8080/logout
    oauth2: 
      client: 
        provider: 
          ala: 
            issuer-uri: "https://auth-test.ala.org.au/cas/oidc"
        registration: 
          ala: 
            client-id: "<<< Add in external configuration, set by ansible, sourced from CAS Management App >>>>"
            client-secret: "<<< Add in external configuration, set by ansible, sourced from CAS Management App >>>>"
```

### External configuration for legacy API keys and whitelists

```yaml
spring:
  security:
    legacy:
      roles: 'ROLE_ADMIN' #comma separated list
      whitelist:
        email: myapp@ala.org.au
        userId: '99999'      
        enabled: true        
        ip: '127.0.0.1,123.123.123.123' #comma separated list 
      apikey:
        enabled: true        
        serviceUrl: https://auth-test.ala.org.au/apikey/....
```

### Demo application

A demo application that uses this plugin is here: <<< TO_BE_ADDED >>

## Calling services with JSON Web Tokens

JWTs can be generated using the service:  <<< TO_BE_ADDED >>

## Calling services with Legacy API key

From the client side, set the ```apiKey``` request _header_  on all secured service requests to a valid API Key (registered in the API Key service).

## Annotations
Controllers for webservice and UI methods can be protected either the class or individual methods with the ```@RequireAuth``` annotation.
A set of roles can be included.

```groovy
@RequireAuth
def saveEntity(){
// do stuff
}

@RequireAuth(["ROLE_ADMIN"])
def deleteEntity(){
 // do stuff
}

```

## Changelog
- **Version 3.0**
  - JSON Web Token support
  - Spring Security
  - Role based authentication for web service
- **Version 2.0**
  - Grails 3 version
- **Version 1.0** (2/7/2015)
  - Initial release.
  - Includes a grails filter and a ```RequireApiKey``` annotation for securing web service calls via the ALA API Key infrastructure.
