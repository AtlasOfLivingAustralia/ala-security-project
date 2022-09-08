# ala-ws-security-plugin
Web service specific security code, e.g. API Key filters

## Status
[![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin)

## Usage
```
compile "org.grails.plugins:ala-ws-security-plugin:4.2.0-SNAPSHOT"
```

### JWT Usage

From the client side, send an Authorization: Bearer request _header_ on all secured service requests, with a JWT access token issued by an OIDC IdP as the payload.

On the server side, the legacy `@RequireApiKey` annotations will still be honoured, but will
look for a JWT in the request first before optionally falling back to the legacy behaviour.

Optionally, you may add a `scopes` parameter to the `@RequireApiKey` annotation, to enforce incoming JWT
requests to have the given scopes (ie, an app might have a `read:appname` scope defined for reading from its API)

### Legacy Usage

From the client side, set the ```apiKey``` request _header_  on all secured service requests to a valid API Key (registered in the API Key service).

On the server side, annotate protected controllers (either the class or individual methods) with the ```RequireApiKey``` annotation.

## External configuration properties

### JWT support
- ```security.jwt.enabled``` - Defaults to true.  True indicates the plugin should check for JWTs on incoming requests.
- ```security.jwt.discovery-uri``` - The discovery URI of the OIDC provider.  JWT validation will be bootstrapped from this document.
- ```security.jwt.connect-timeout-ms``` - HTTP request connection timeout
- ```security.jwt.read-timeout-ms``` - HTTP request read timeout
- ```security.jwt.required-claims``` - The claims that must be present on the JWT for it to be valid.  By default this is `"sub", "iat", "exp", "nbf", "cid", "jti"`
- ```security.jwt.required-scopes``` - List of scopes that are required for all JWT endpoints in this app

### ApiKey support
- ```security.apikey.enabled``` - Defaults to false. True indicated the plugin should check for apikey on incoming requests.

#### Mandatory
- ```security.apikey.check.serviceUrl``` - URL of the API Key service endpoint, up to and including the key parameter name. E.g. https://auth.ala.org.au/apikey/ws/check?apikey=
- ```security.apikey.userdetails.serviceUrl``` - URL of the userdetails service endpoint. E.g. https://auth.ala.org.au/userdetails/getUserDetails
#### Optional
- ```security.apikey.header.override``` - override the default request header name (apiKey) to use a different name.
- ```security.apikey.header.alternatives``` - alternate request header names to check if the default request header (`apiKey`) is not found

### IP whitelist support
- ```security.ip.whitelist``` - comma separated list of IP Addresses that are exempt from the API key security check. If the property is not defined then IP whitelisting is disabled.

## Changelog
- **Version 4.0.0**
  - Grails 4 version
  - Add JWT support
- **Version 2.0**
  - Grails 3 version
- **Version 1.0** (2/7/2015)
  - Initial release.
  - Includes a grails filter and a ```RequireApiKey``` annotation for securing web service calls via the ALA API Key infrastructure.
