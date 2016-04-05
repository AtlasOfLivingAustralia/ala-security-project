# ala-ws-plugin
Grails plugin containing common REST and general webservice functionality

# Status
[![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-plugin.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/ala-ws-plugin)


# Usage

```
runtime ":ala-ws-plugin:x.y.z"
```


## The WebService class

This is intended as a common replacement for all application-specific implementations of the WebService class. It supports the following functionality:

See the groovydoc for API documentation.

```
// Inject the WebService class
WebService webService

...
// Invoke a service using the HTTP verb (get, post, put, delete)
webService.post(...)
```

All operations return a Map with the following structure: 

For JSON request types:
```[statusCode: int, resp: [:]]``` on success, where ```resp``` is a Map containing the JSON response object, or ```[statusCode: int, error: string]``` on error, where ```error``` is the error message or HTTP status message.


# External configuration properties
 
* ```webservice.apiKey``` The ALA api key to be included in each request (in the ```apiKey``` header field) when ```includeApiKey = true```. API Keys are intended to be used with the [ALA WS Security Plugin](https://github.com/AtlasOfLivingAustralia/ala-ws-security-plugin).
* ```webservice.timeout``` The timeout setting for all web service requests (default is 5 minutes). The same timeout value is used for Connect, Read and Socket timeouts.
* ```app.http.header.userId``` The header name for the ALA user details (used by the auth framework). Defaults to X-ALA-userId.

# Integration Testing

This plugin uses [Ratpack](http://ratpack.io) to set up an embedded http server for the tests. Ratpack makes doing this extremely easy, and allows us to write integration tests which invoke real http services so we can check that the WebService class has set the appropriate headers, cookies, etc.

Ratpack requires Java 1.8, so if you are modifying this plugin, be sure to use jdk8.

# Dev environment set up

1. Clone the repo
1. Import the source into your IDE
1. Use Grails version 2.5.2
1. Use JDK 1.8

To test changes locally, set the plugin as a local plugin on a grails application:

1. In the host application's BuildConfig.groovy
  1. Comment out (if present) the existing dependency on ala-ws-plugin
  1. Add ```grails.plugin.location.ala-ws-plugin = "/path/to/local/ala-ws-plugin"```
  
  