package au.org.ala.ws.service

import au.org.ala.web.AuthService
import grails.converters.JSON
import grails.test.spock.IntegrationSpec
import org.apache.commons.logging.Log
import org.apache.http.HttpStatus
import org.apache.http.entity.ContentType
import ratpack.exec.Promise
import ratpack.form.Form
import ratpack.groovy.test.embed.GroovyEmbeddedApp
import ratpack.http.TypedData
import ratpack.test.embed.EmbeddedApp
import spock.lang.Shared

class WebServiceSpec extends IntegrationSpec {

    WebService service
    @Shared
    EmbeddedApp server
    @Shared
    String url

    def setupSpec() {
        /* https://ratpack.io/manual/current/all.html */
        server = GroovyEmbeddedApp.of {
            handlers {
                get("success") {
                    render '{"hello": "world"}'
                }
                get("fail") {
                    context.clientError(HttpStatus.SC_BAD_REQUEST)
                }
                get("headers") {
                    Map incomingHeaders = context.getRequest().getHeaders().asMultiValueMap()?.collectEntries { it }

                    def json = [headers: incomingHeaders] as JSON

                    render json.toString(true)
                }
                post("post") {
                    Promise body = context.getRequest().getBody()
                    body.then { TypedData b ->
                        def json = [contentType: b.getContentType()?.getType(), bodyText: b.getText()] as JSON

                        render json.toString(true)
                    }
                }
                post("postMultipart") {
                    Promise body = context.parse(Form)
                    body.then { Form f ->
                        List files = []
                        f.files().each { files << it.value.fileName }
                        def json = [files: files] as JSON

                        render json.toString(true)
                    }
                }
            }
        }

        url = server.getAddress().toString()
        println "Running embedded Ratpack server at ${url}"
    }

    def setup() {
        service = new WebService()
        service.authService = Mock(AuthService)
        service.authService.userDetails() >> [userId: "1234", email: "fred@bla.com"]
        service.grailsApplication = [
                config: [
                        webservice: [
                                timeout: 10,
                                apiKey : "myApiKey"
                        ],
                        app       : []
                ]
        ]
    }

    def cleanupSpec() {
        server?.close()
    }

    def "a request that results in a connection exception should return a statusCode == 500 and an error message, and log the error"() {
        setup:
        service.log = Mock(Log)

        when: "the call results in a 404 (i.e. there is no server running)"
        Map result = service.get("http://localhost:123123")

        then:
        result.error != null
        result.statusCode == HttpStatus.SC_INTERNAL_SERVER_ERROR
        1 * service.log.error(_, _)
    }

    def "a successful request should return a map with statusCode == 200 and resp JSON object"() {
        when:
        Map result = service.get("${url}/success")

        then:
        !result.error
        result.statusCode == HttpStatus.SC_OK
        result.resp == [hello: "world"]
    }

    def "a failed request should return a map with the server status code and an error message"() {
        when:
        Map result = service.get("${url}/fail")

        then:
        result.error != null
        result.statusCode == HttpStatus.SC_BAD_REQUEST
        !result.resp
    }

    def "a request should include the ALA auth header and cookie if includeUser = true"() {
        when:
        Map result = service.get("${url}/headers", false, true)

        then:
        result.resp.headers['Cookie'] == "ALA-Auth=fred%40bla.com" // url encoded email address
        result.resp.headers['X-ALA-userId'] == "1234"
    }

    def "a request should include the ALA API Key header if includeApiKey = true"() {
        when:
        Map result = service.get("${url}/headers", true, false)

        then:
        result.resp.headers['apiKey'] == "myApiKey"
    }

    def "The request content type should be JSON"() {
        when:
        Map result = service.post("${url}/post", [foo: "bar"])

        then:
        result.resp.contentType == ContentType.APPLICATION_JSON.getMimeType()
        result.resp.bodyText == '{"foo":"bar"}'
    }

//    def "Passing a list of files to postMultipart() should result in a MultiPart request"() {
//        when:
//        Map result = service.postMultipart("${url}/postMultipart", [foo: "bar"], ["file1".bytes, "file2".bytes])
//
//        then:
//        result.resp.files.length == 2
//    }
}