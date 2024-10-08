# ala-ws-security-plugin
Web service specific security code, e.g. API Key filters

## Status
[![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-security-plugin)

## Usage
```
compile "org.grails.plugins:ala-ws-security-plugin:4.4.0-SNAPSHOT" // Grails
compile "au.org.ala.ala-ws-spring-security:4.4.0-SNAPSHOT" // Spring Boot w/ Spring Security
```

### JWT Usage

From the client side, send an Authorization: Bearer request _header_ on all secured service requests, with a JWT access token issued by an OIDC IdP as the payload.

On the server side, the legacy `@RequireApiKey` annotations will still be honoured, but will
look for a JWT in the request first before optionally falling back to the legacy behaviour.

Optionally, you may add a `scopes` parameter to the `@RequireApiKey` annotation, to enforce incoming JWT
requests to have the given scopes (ie, an app might have a `appname/read` scope defined for reading from its API).
For the case where scopes shouldn't be hard coded in to the application, the `scopesFromProperty` parameter on
`@RequireApiKey` can be set, and the scopes will be read from the given configuration property.

Additionally, a custom filter can be defined to implement custom business logic for authorising requests.  To do so,
simply define a bean of type `au.org.ala.ws.security.filter.RequireApiKeyFilter` in your application context.  This
filter is called after the JWT has been validated, and before the request is passed to the controller.  To access
the parsed JWT access token anywhere within the application, use 
`request.getAttribute(AlaOidcAuthenticator.JWT_ACCESS_TOKEN_ATTRIBUTE)`.

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
- ```security.jwt.prohibited-claims``` - The claims that must *not* be present on the JWT for it to be valid.  By default this is empty, ie no claims are prohibited.
- ```security.jwt.required-scopes``` - List of scopes that are required for all JWT endpoints in this app
- ```security.jwt.user-id-claim``` - The claims from the access token that contains the userId (default: `userid`)
- ```security.jwt.role-claims``` - The name of the claim(s) that contain the roles (default: `role`)
- ```security.jwt.permission-claims``` - The name of the claims(s) that contain the permissions (default: `scope,scopes,scp`)
- ```security.jwt.roles-from-access-token``` - should the role claims be read from the access_token (default: `true`)
- ```security.jwt.role-prefix``` - The prefix to apply to the access token roles (eg. `ROLE_`)
- ```security.jwt.role-to-uppercase``` - Should the role be converted to upper case (default: `true`)
- ```security.jwt.accepted-audiences``` - If provided then only these audience values will be accepted. If not provided then any audience will be accepted.

### ApiKey support
- ```security.apikey.enabled``` - Defaults to false. True indicated the plugin should check for apikey on incoming requests.

#### Mandatory
- ```security.apikey.auth.serviceUrl``` - **NOTE:  Changed** URL of the API Key service endpoint, up to the context path. E.g. https://auth.ala.org.au/apikey/
- ```security.apikey.userdetails.serviceUrl``` - URL of the userdetails service endpoint. E.g. https://auth.ala.org.au/userdetails/
#### Optional
- ```security.apikey.header.override``` - override the default request header name (apiKey) to use a different name.
- ```security.apikey.header.alternatives``` - alternate request header names to check if the default request header (`apiKey`) is not found

### IP whitelist support
- ```security.ip.whitelist``` - comma separated list of IP Addresses that are exempt from the API key security check. If the property is not defined then IP whitelisting is disabled.

## Changelog
- ** Version 4.4.0 **
  - Spring Boot Support
- **Version 4.0.0**
  - Grails 4 version
  - Add JWT support
- **Version 2.0**
  - Grails 3 version
- **Version 1.0** (2/7/2015)
  - Initial release.
  - Includes a grails filter and a ```RequireApiKey``` annotation for securing web service calls via the ALA API Key infrastructure.
