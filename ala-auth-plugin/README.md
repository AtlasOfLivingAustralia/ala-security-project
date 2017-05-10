# ala-auth-plugin [![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-auth-plugin.svg?branch=grails2)](https://travis-ci.org/AtlasOfLivingAustralia/ala-auth-plugin)
## Usage
```
runtime ":ala-auth:2.0.2"
```

## Description
ALA authentication/authorization plugin interface to CAS

## Usage

### Setup CAS Authentication for your app

In your `Config.groovy` you should define the following properties:

```groovy
security {
    cas {
        appServerName = 'http://devt.ala.org.au:8080' # or similar, up to the request path part
        uriFilterPattern = '/paths/.*,/that,/require/.*,/auth.*'
        uriExclusionFilterPattern = '/assets/.*,/images/.*,/css/.*,/js/.*,/less/.*' # this is the default value
        authenticateOnlyIfLoggedInPattern =  '/optional-auth/.*'
    }
}
```

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
    }
}
```

`ala-cas-client` v2.3+ will now get the context path from the Servlet Context, so that property is
no longer required.

### (Optional) Add role based authorization using the @AlaSecured annotation

On a Grails controller, you can use the @AlaSecured annotation to do role based authorization for
Grails actions.

### Use a different user details location

You can change the base address of the UserDetails web services by overriding the following config value:

```groovy
userDetails.url = 'https://auth.ala.org.au/userdetails/'
```

## Changelog
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
