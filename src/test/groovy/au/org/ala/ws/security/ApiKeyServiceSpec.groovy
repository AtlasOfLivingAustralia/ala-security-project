package au.org.ala.ws.security

import au.org.ala.ws.security.service.ApiKeyService
import au.org.ala.ws.security.service.WsService
import grails.testing.services.ServiceUnitTest
import org.grails.spring.beans.factory.InstanceFactoryBean
import org.springframework.http.HttpStatus
import spock.lang.Specification
import spock.lang.Unroll

@Unroll
class ApiKeyServiceSpec extends Specification implements ServiceUnitTest<ApiKeyService> {


    def setup() {
        defineBeans {
            wsService(InstanceFactoryBean, new MockWebService(200))
        }
    }

    void "Should return valid = false when the API Key service returns a HTTP code other than 200"() {
        setup:
        service.grailsApplication.config.put('security.apikey.check.serviceUrl', 'bla')

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
        service.grailsApplication.config.put('security.apikey.check.serviceUrl', 'bla')

        when:
        service.wsService = new MockWebService(HttpStatus.OK.value(), "{valid: true}")
        Map result = service.checkApiKey("bla")

        then:
        result.valid?.toBoolean() == true
    }

    void "Should return valid = false if the API Key service returns a HTTP 200 and a response JSON of '{valid: false}'"() {
        setup:
        service.grailsApplication.config.put('security.apikey.check.serviceUrl', 'bla')

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
