# userdetails-service-client [![Build Status](https://travis-ci.org/AtlasOfLivingAustralia/userdetails-service-client.svg?branch=master)](https://travis-ci.org/AtlasOfLivingAustralia/userdetails-service-client)

A Java client for the [UserDetails](https://github.com/AtlasOfLivingAustralia/userdetails) webservices.

This client uses [Square's](https://square.github.io/) [Retrofit](http://square.github.io/retrofit/) to generate a client based on the high performance [OkHttp](http://square.github.io/okhttp/) and [Moshi JSON parser](https://github.com/square/moshi) libraries.

To use this client you will also need to provide a Bearer token header in your Call.Factory, see ala-auth-plugin or ala-ws-security-plugin for an example Grails implementation.
