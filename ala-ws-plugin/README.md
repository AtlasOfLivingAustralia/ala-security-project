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


## Request Validation

The Grails recommended way to validate request parameters is to use either a Domain or a Command object, and implement the ```static constraints = {...}``` closure. E.g.

```
class MyController {
  def action1(ActionCommand command) {
    if (command.hasErrors()) {
      response.status = HttpStatus.SC_BAD_REQUEST
      response.sendError(HttpStatus.SC_BAD_REQUEST, command.errors.join(";"))
    } else {
      // do stuff
    }
  }
}

@grails.validation.Validateable
class ActionCommand {
  String param1
  String param2
  
  static constraints = {
    param1 nullable: true
    params2 minSize: 6
  }
}
```
 
A more generalised validation approach is to use the [Bean Validation](http://beanvalidation.org/) standard. 
See [the JavaEE 6 doco](http://docs.oracle.com/javaee/6/api/javax/validation/constraints/package-summary.html) for a 
list of available annotations.

This plugin provides a basic implementation of a grails filter that will valid requests using JSR-303 annotations. 
Any validation errors will result in a HTTP 400 (BAD_REQUEST). This pulls the validation code and the subsequent error
handling out of the controller, allowing you to just annotate your actions and otherwise ignore validation. E.g.

```
class MyController {
  def action1(@NotNull String param1, @Min(6) String param2) {
    // do stuff
  }
```
This is equivalent in functionality to the Command Object example above, except you'll get a better error message.

As per the bean validation spec, any validation constraint annotation (including custom annotations, as long as the 
annotation is annotated with @Constrain meta-annotation) can be used to validate the request parameters.

# External configuration properties
 
* ```webservice.apiKey``` The ALA api key to be included in each request (in the ```apiKey``` header field) when ```includeApiKey = true```. API Keys are intended to be used with the [ALA WS Security Plugin](https://github.com/AtlasOfLivingAustralia/ala-ws-security-plugin).
* ```webservice.apiKeyHeader``` Override the default name of the apiKey header. This applied to all service calls - if you need to change the name for a single service, then you'll need to pass in the api key in a custom header via the API.
* ```webservice.connect.timeout``` The connect timeout setting for all web service requests (default is 5 minutes). 
* ```webservice.read.timeout``` The read timeout setting for all web service requests (default is 5 minutes). 
* ```webservice.socket.timeout``` The socket timeout setting for all web service requests (default is 5 minutes).
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
  
  