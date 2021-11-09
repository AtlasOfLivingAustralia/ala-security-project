# ala-ws-security-plugin
Web service specific security code, e.g. API Key filters

## Status
[![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin)

This plugin provides authentication and authorization for Atlas web services written in Grails.
It support JSON Web Token authentication. 
It also supports the deprecated apikeys used for internal-app to internal-app. These api keys are to be phased
out in favour of JWTs which can be used for internal and external web service calls.

## Usage

To use this plugin, you will need to include the following dependency in build.gradle

```
compile "org.grails.plugins:ala-ws-security-plugin:3.0.0-SNAPSHOT"
```

In addition, you will need to the following bean definition to `grails-app/conf/spring/resources.groovy`.

```groovy
package spring

import au.ala.org.ws.security.AlaAuthFilter

// Place your Spring DSL code here
beans = {
    authFilter(AlaAuthFilter)
    securityConfig(SecurityConfig)
}
```







From the client side, set the ```apiKey``` request _header_  on all secured service requests to a valid API Key (registered in the API Key service).

On the server side, annotate protected controllers (either the class or individual methods) with the ```RequireApiKey``` annotation.

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
