# ala-auth-plugin [![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-auth-plugin.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/ala-auth-plugin)
## Usage
```
compile "org.grails.plugins:ala-auth:3.2.0"
```

## Description
ALA authentication/authorization Grails 3 plugin interface to CAS.  The Grails 2 version of this plugin can
be found on the grails2 branch.

## Usage

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
        uriFilterPattern = ['/paths/*','/that','/require/*,'/auth/**'] // Java servlet filter style paths only
        authenticateOnlyIfCookieFilterPattern =  ['/optional-auth/*'] // Will force CAS auth if the Auth Cookie is defined
        gatewayFilterPattern = ['/api/**'] // Use CAS gateway requests for these paths
        gatewayIfCookieFilterPattern = ['/sso-only/**'] // Uses CAS gateway requests for these paths if the Auth Cookie is defined
        uriExclusionFilterPattern = ['/paths/anonymous'] // Regex paths supported, only necessary to exclude a path from one / all of the above.
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

### Migration from 1.x

See [this page](https://github.com/AtlasOfLivingAustralia/ala-auth-plugin/wiki/1.x-Migration-Guide) on the wiki for steps to upgrade from 1.x.

## Changelog
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
