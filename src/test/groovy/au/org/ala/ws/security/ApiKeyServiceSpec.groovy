package au.org.ala.ws.security

import au.org.ala.ws.security.service.ApiKeyService
import au.org.ala.ws.security.service.WsService
import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import org.springframework.http.HttpStatus
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(ApiKeyService)
@Unroll
@Mock(WsService)
class ApiKeyServiceSpec extends Specification {

    void "Should return valid = false when the API Key service returns a HTTP code other than 200"() {
        setup:
        ApiKeyService service = new ApiKeyService()

        service.grailsApplication = [config: [security: [apikey: [check: [serviceUrl: "bla"]]]]]

        when:
        service.wsService = new MockWebService(status)
        Map result = service.checkApiKey("bla")

        then:

        if (status == HttpStatus.OK.value) {
            assertTrue "HTTP Status ${status} - The result should be valid (true) when the web service returns a HTTP 200", result.valid?.asBoolean()
        } else {
            assertFalse "HTTP Status ${status} - The result should be invalid (false) when the web service returns anything other than a HTTP 200", result.valid?.asBoolean()
        }

        where: status << HttpStatus.values().collect { it.value }
    }

    void "Should return valid = true if the API Key service returns a HTTP 200 and a response JSON of '{valid: true}'"() {
        setup:
        ApiKeyService service = new ApiKeyService()

        service.grailsApplication = [config: [security: [apikey: [check: [serviceUrl: "bla"]]]]]

        when:
        service.wsService = new MockWebService(HttpStatus.OK.value(), "{valid: true}")
        Map result = service.checkApiKey("bla")

        then:
        assertTrue "The result should be valid (true) when the web service returns a HTTP 200 with json '{valid: true}'", result.valid?.asBoolean()
    }

    void "Should return valid = false if the API Key service returns a HTTP 200 and a response JSON of '{valid: false}'"() {
        setup:
        ApiKeyService service = new ApiKeyService()

        service.grailsApplication = [config: [security: [apikey: [check: [serviceUrl: "bla"]]]]]

        when:
        service.wsService = new MockWebService(HttpStatus.OK.value(), "{valid: false}")
        Map result = service.checkApiKey("bla")

        then:
        assertFalse "The result should be invalid (false) when the web service returns a HTTP 200 with json '{valid: false}'", result.valid?.asBoolean()
    }
}

class MockWebService extends WsService {
    int statusCode
    String responseJSON

    MockWebService(int statusCode) {
        this(statusCode, "{valid: true}")
    }

    MockWebService(int statusCode, String responseJSON) {
        this.statusCode = statusCode
        this.responseJSON = responseJSON
    }

    @Override
    def get(String url) {
        return [responseCode: statusCode, content: [text: responseJSON]]
    }
}
