# ala-auth-plugin [![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-auth-plugin.svg?branch=grails2)](https://travis-ci.org/AtlasOfLivingAustralia/ala-auth-plugin)
## Usage
```
runtime ":ala-auth:2.1.3"
```

## Description
ALA authentication/authorization plugin interface to CAS

## Usage

### Setup CAS Authentication for your app

In your `Config.groovy` you should define the following properties:

```groovy
security {
    cas {
        appServerName = 'http://devt.ala.org.au:8080' // or similar, up to the request path part
        // service = 'http://devt.ala.org.au:8080' // optional, if set it will always be used as the return path from CAS
        uriFilterPattern = '/paths/.*,/that,/require/.*,/auth.*'
        uriExclusionFilterPattern = '/assets/.*,/images/.*,/css/.*,/js/.*,/less/.*' // this is the default value
        authenticateOnlyIfLoggedInPattern =  '/optional-auth/.*'
    }
}
```

**NOTE** If setting `security.cas.appServerName` only and a scheme / port number is not specified: ensure that the app 
server (eg Tomcat) is receiving the correct remote scheme / port from any reverse proxy (eg by using the AJP protocol 
or enabling the Tomcat Remote IP Valve and the appropriate headers from the RP) otherwise the CAS filter will get 
confused trying to generate the service url for the CAS callback.

The remaining properties should have sensible default values that are provided by this plugin.  You can
override these if you wish, however:

```groovy
security {
    cas {
        casServerName = 'https://auth.ala.org.au'
        casServerUrlPrefix = 'https://auth.ala.org.au/cas'
        loginUrl = 'https://auth.ala.org.au/cas/login'
        logoutUrl = 'https://auth.ala.org.au/cas/logout'
        bypass = false
        roleAttribute = 'authority'
        ignoreCase = true
    }
}
```

`ala-cas-client` v2.3+ will now get the context path from the Servlet Context, so that property is
no longer required but can be set to override this behaviour.

### (Optional) Add role based authorization using the @AlaSecured annotation

On a Grails controller, you can use the @AlaSecured annotation to do role based authorization for
Grails actions.

### Use a different user details location

You can change the base address of the UserDetails web services by overriding the following config value:

```groovy
userDetails.url = 'https://auth.ala.org.au/userdetails/'
```

## Changelog
- **Version 2.1.3** (17/06/2017):
  - Don't call userdetails service for a blank username.
- **Version 2.1.2** (7/06/2017):
  - Adjust filter order slightly, so that CAS filters happen before Grails filter and preserve flash scope variables.
- **Version 2.1.1** (3/06/2017):
  - Add roleAttribute proprty so that `HttpServletRequest.isUserInRole(String)` works
  - Add ignoreCase proprty so that `HttpServletRequest.isUserInRole(String)` works the same as previous versions of the plugin
  - Add SingleSignOut Http Session Listener to clean out SingleSignOut filter on session expiry.
- **Version 2.1** (12/05/2017):
  - Fix order the CAS filters are run
- **Version 2.0** (24/02/2017):
  - Upgrade to latest ALA CAS client (and latest JASIG CAS client)
  - Allow CAS configuration to be read from regular `grailsApplication.config` at runtime
  - Use [AtlasOfLivingAustralia/userdetails-service-client](https://github.com/AtlasOfLivingAustralia/userdetails-service-client) instead of `HttpWebService` to provide UserDetails
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
