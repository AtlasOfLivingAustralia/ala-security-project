package au.org.ala.ws.security


import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import org.springframework.http.HttpStatus
import spock.lang.Specification
import spock.lang.Unroll

@TestFor(LegacyApiKeyService)
@Unroll
@Mock(WsService)
class LegacyApiKeyServiceSpec extends Specification {

    void "Should return valid = false when the API Key service returns a HTTP code other than 200"() {
        setup:
        LegacyApiKeyService service = new LegacyApiKeyService()

        service.grailsApplication = [config: [security: [apikey: [check: [serviceUrl: "bla"]]]]]

        when:
        service.wsService = new MockWebService(status)
        Map result = service.checkApiKey("bla")

        then:

        if (status == HttpStatus.OK.value()) {
            result.valid?.toBoolean() == true
        } else {
            result.valid?.toBoolean() == false
        }

        where: status << HttpStatus.values().collect { it.value() }
    }

    void "Should return valid = true if the API Key service returns a HTTP 200 and a response JSON of '{valid: true}'"() {
        setup:
        LegacyApiKeyService service = new LegacyApiKeyService()

        service.grailsApplication = [config: [security: [apikey: [check: [serviceUrl: "bla"]]]]]

        when:
        service.wsService = new MockWebService(HttpStatus.OK.value(), "{valid: true}")
        Map result = service.checkApiKey("bla")

        then:
        result.valid?.toBoolean() == true
    }

    void "Should return valid = false if the API Key service returns a HTTP 200 and a response JSON of '{valid: false}'"() {
        setup:
        LegacyApiKeyService service = new LegacyApiKeyService()

        service.grailsApplication = [config: [security: [apikey: [check: [serviceUrl: "bla"]]]]]

        when:
        service.wsService = new MockWebService(HttpStatus.OK.value(), "{valid: false}")
        Map result = service.checkApiKey("bla")

        then:
        result.valid?.toBoolean() == false
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
