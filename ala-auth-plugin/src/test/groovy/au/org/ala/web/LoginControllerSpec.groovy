package au.org.ala.web

import grails.testing.web.controllers.ControllerUnitTest
import org.grails.spring.beans.factory.InstanceFactoryBean
import spock.lang.Specification

class LoginControllerSpec extends Specification implements ControllerUnitTest<LoginController> {

    def mockSsoStrategy = Mock(SSOStrategy)

    def setup() {
        defineBeans {
            ssoStrategy(InstanceFactoryBean, mockSsoStrategy, SSOStrategy)
        }
    }

    def cleanup() {
    }

    void "test log in action"() {
        given:
        def path = '/test'
        1 * mockSsoStrategy.authenticate(request,response,false,_) >> { request, response, gateway, pathArg ->
            response.setStatus(302)
            response.setHeader('Location', "http://localhost/oidc/authorize?clientid=test&secret=test&redirectUrl=$pathArg")
            true
        }

        when:"login without authenticated user"
        params.path = path
        controller.index()

        then:"redirected to identity provider"
        response.redirectedUrl == 'http://localhost/oidc/authorize?clientid=test&secret=test&redirectUrl=http://localhost:8080/test'
    }


    void "test already logged in action"() {
        given:
        def path = '/test'
        1 * mockSsoStrategy.authenticate(request,response,false,_) >> false

        when:"login with authenticated user"
        params.path = path
        controller.index()

        then:"redirected to page straight away"
        response.redirectedUrl == 'http://localhost:8080/test'
    }
}
