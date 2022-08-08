# ala-auth-plugin [![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-auth-plugin.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/ala-auth-plugin)
## Usage
```
compile "org.grails.plugins:ala-auth:5.1.1"
```

## Description
ALA authentication/authorization Grails 4 plugin interface to CAS.  
The Grails 3 version of this plugin can be found under the 3.x branches.  
The Grails 2 version of this plugin can be found on the grails2 branch.

### Upgrade notes

Grails 4 version of the plugin now provides a OpenID Connect option for authenticating users.

*NOTE*: This plugin currently requires JDK11 due to the use of PAC4j, which itself requires JDK11.  
A JDK8 version using the last version of PAC4j that supports JDK8 may be possible if required.

To enable it, you must disable CAS and enable OpenID Connect like so:

```yaml
security:
  cas:
    enabled: false
  oidc:
    enabled: true
```

To configure the OpenID Connect provider, you may set the following properties:

```yaml
security:
  oidc:
    discovery-uri: 'https://auth.ala.org.au/cas/oidc/.well-known'
    client-id: 'ChangeMe'
    secret: 'ChangeMe'
    scope: 'openid profile email ala roles'
```

`discovery-uri` can use auth-test or auth-dev instead.

The scopes available are:
 - `openid` must be present for OpenID Connect
 - `profile` contains the user's name
 - `email` contains the user's email
 - `ala` contains ALA extended attributes
 - `roles` to get the user's roles.

## Usage

Select one of CAS or OpenID Connect authentication and then follow the guide for that
auth system.  Note that OIDC is preferred going forward.

### Setup OpenID Connect Authentication for your app

To configure the OpenID Connect provider, you may set the following properties:

```yaml
security:
  cas:
    enabled: false // default is true, undefined behaviour if this omitted
  oidc:
    enabled: true // default is false
    discovery-uri: 'https://auth.ala.org.au/cas/oidc/.well-known'
    client-id: 'ChangeMe'
    secret: 'ChangeMe'
    scope: 'openid profile email ala roles'
```

For ease of transition, the following old property names are accepted for configuring the OIDC authn:

```yaml
security:
  cas:
    uriFilterPattern: ['/paths/*','/that','/require/*,'/auth/*'] // Java servlet filter style paths only
    authenticateOnlyIfCookieFilterPattern:  ['/optional-auth/*'] // Will force OIDC auth if the Auth Cookie is defined
    gatewayFilterPattern: ['/api/*'] // Use OIDC prompt=none
    gatewayIfCookieFilterPattern: ['/sso-only/*'] // Use OIDC prompt=none for these paths if the Auth Cookie is defined
    uriExclusionFilterPattern: ['/paths/anonymous/.*', 'https?://.*/.*\?ignoreCas=true'] // Regex URLs supported, only necessary to exclude a path from one / all of the above.
```

TODO: OIDC prefix versions of these.

For local development, dev and test deployments `discovery-uri` should be set to auth-test or auth-dev instead.

The scopes available are:
- `openid` must be present for OpenID Connect
- `profile` contains the user's name
- `email` contains the user's email
- `ala` contains ALA extended attributes
- `roles` to get the user's roles.

#### Register your OpenID Connect app

Head to the CAS Management app and add an OpenID Connect Relying Party.  For local development, the dev and test environments
may already have existing RPs that you can use.

- Add the redirect URI, which is regex, so can be of the form `https?://app.ala.org.au/.*`
- Ensure the JWKS is set to the correct path to the JWKS
- Ensure that the scopes list all the scopes required by your application
- To participate in Single Sign Out, add a logout handler URL of `<baseURL>/callback?logoutendpoint`

Take the client id and secret from the RP registration and add them to your app's external config under
`security.oidc.client-id` and `security.oidc.secret`.

### Setup CAS Authentication for your app

In your `application.yml` or `application.groovy` you should define the following
properties:

**NOTE** `uriFilterPattern`, `authenticateOnlyIfLoggedInFilterPattern` and `uriExclusionFilterPattern` have changed:
 - All properties are now lists instead of comma separated strings,
 - Only the `uriExclusionFilterPattern` supports regexes now, all others only support Java Servlet Filter paths,

```groovy
security {
    cas {
        appServerName = 'http://devt.ala.org.au:8080' // or similar, up to the request path part
        uriFilterPattern = ['/paths/*','/that','/require/*,'/auth/*'] // Java servlet filter style paths only
        authenticateOnlyIfCookieFilterPattern =  ['/optional-auth/*'] // Will force CAS auth if the Auth Cookie is defined
        gatewayFilterPattern = ['/api/*'] // Use CAS gateway requests for these paths
        gatewayIfCookieFilterPattern = ['/sso-only/*'] // Uses CAS gateway requests for these paths if the Auth Cookie is defined
        uriExclusionFilterPattern = ['/paths/anonymous/.*', 'https?://.*/.*\?ignoreCas=true'] // Regex URLs supported, only necessary to exclude a path from one / all of the above.
    }
}
```

**NOTE** If setting `security.cas.appServerName` only and a scheme / port number is not specified: ensure that the app
server (eg Tomcat) is receiving the correct remote scheme / port from any reverse proxy (eg by using the AJP protocol
or enabling the Tomcat Remote IP Valve and the appropriate headers from the RP) otherwise the CAS filter will get
confused trying to generate the service url for the CAS callback.

The remaining properties should have sensible default values that are provided by this plugin.  You can
override these if you wish, however:

```yaml
security:
    cas:
        casServerName: https://auth.ala.org.au
        casServerUrlPrefix: https://auth.ala.org.au/cas
        loginUrl: https://auth.ala.org.au/cas/login
        logoutUrl: https://auth.ala.org.au/cas/logout
        bypass: false
        roleAttribute: authority
        ignoreCase: true
        renew: false
        authCookieName: 'ALA-Auth'
```

`ala-cas-client` v2.3+ will now get the context path from the Servlet Context, so that property is
no longer required.

### (Optional) Replace or add authentication using the @SSO annotation

Instead of (or as well as) specifying URIs for authentication using the `security.cas.uriFilterPattern` property (and 
friends), v3.2 of the plugin introduces applying an `@SSO` annotation to a controller or action, allowing said 
controller/action to always ensure authentication via CAS regardless of how it's defined in URL mapping.

The `@SSO` annotation also supports the following arguments:

 - `gateway` - Use a CAS gateway request
 - `cookie` - Only force authentication if the ALA Auth cookie is present

If `@SSO` is applied to a controller and an action within the controller doesn't require authentication
then a corresponding `@NoSSO` annotation may be used to opt out of the authentication for that action, eg:

```groovy

@SSO
class TestController {

  def index() {
    log.debug('username should always be present: {}', request.userName)
  }
  
  @NoSSO
  def info() {
    log.debug('username may not be present if this action is accessed directly: {}', request.userName)
  }

}
```

Also note that if a URI in `security.cas.uriFilterPattern` covers a controller / action which has been annotated then the
`security.cas.uriFilterPattern` version will take precedence (with regard to gateway / cookie settings)

### (Optional) Add role based authorization using the @AlaSecured annotation

On a Grails controller, you can use the `@AlaSecured` annotation to do role based authorization for
Grails actions.

### Use a different user details location

You can change the base address of the UserDetails web services by overriding the following config value:

```groovy
userDetails.url = 'https://auth.ala.org.au/userdetails/'
```

### AuthService configuration

The AuthService Grails service calls web services on the UserDetails application.  To ensure that these
calls include a bearer access token you must provide a `jwtInterceptor` bean.  This bean should implement the
okhttp interceptor interface and insert a Bearer token in the Authorization header containing a client
credentials grant with the required scopes for the service (typically `users:read`).  If the `ala-ws-plugin`
is also used, then this step is performed automatically.

### Migration from 1.x

See [this page](https://github.com/AtlasOfLivingAustralia/ala-auth-plugin/wiki/1.x-Migration-Guide) on the wiki for steps to upgrade from 1.x.

## Changelog
- **Version 5.1.1**(5/08/2022):
  - Fix login controller storing redirect URL
- **Version 5.1.0**(25/07/2022):
  - Better Grails 5 experience
  - Update pac4j
  - Add OIDC SLO support for spring session
  - Better support for custom ALA userid attribute
  - Minor fixes and improvements
- **Version 5.0.0** (11/02/2022):
  - Support Grails 4
  - Support OIDC login
- **Version 3.2.3** (10/02/2021):
  - Updated `loginLogout`, supports Grails 3.x apps
- **Version 3.1.3** (10/02/2021):
  - Updated `loginLogout`, supports Grails 3.x apps
- **Version 3.0.5** (10/02/2021):
  - Updated `loginLogout`, supports Grails apps on ala-auth-plugin 3.0.x
- **Version 2.1.6** (10/02/2021):
  - Updated `loginLogout`, supports Grails 2.x apps
  
- **Version 3.2.0**:
  - Add support for using CAS gateway requests for certain paths
  - Convert paths to Java Servlet Filter paths
  - Add authentication via annotation
- **Version 3.1.0**:
  - Updates for ALA CAS 5
  - Update ALA CAS client
  - Update userdetails-service-client
  - Always use the CAS HttpServletRequestFilter to put the CAS principal in the request scope if it's available.
- **Version 3.0.3**:
  - Fix @Cacheable annotations to use the Grails versions instead of Spring
- **Version 3.0.2**:
  - Fix CAS filter registration order WRT the Grails Character Encoding filter.
- **Version 3.0.1**:
  - Support both `authenticateOnlyIfLoggedInPattern` and `authenticateOnlyIfLoggedInFilterPattern` properties for the only if previously logged in filter.
- **Version 3.0.0**:
  - Upgrade to Grails 3
  - Use userdetails-service-client in preference to HttpWebService class
  - Use ala-cas-client 2.3 changes
  - Move servlet context init-param and filter setup into Spring, allowing them to use properties directly from Application.groovy
- **Version 1.3** (07/05/2015):
  - Fixed several URL encoding issues
  - Add support for extra user properties in userdetails web services
  - Add missing config.userDetailsById.bulkPath default setting
- **Version 1.2** (24/02/2015):
  - Excludes the servlet-api dependency from being resolved as a dependency in the host app
- **Version 1.1** (23/02/2015):
  - Added `loginLogout` taglib method
- **Version 1.0** (18/02/2015):
  - Initial release.
