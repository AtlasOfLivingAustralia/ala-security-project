package au.org.ala.web

import grails.testing.web.controllers.ControllerUnitTest
import org.grails.spring.beans.factory.InstanceFactoryBean
import spock.lang.Specification

class LogoutControllerSpec extends Specification implements ControllerUnitTest<LogoutController> {

    static LOGOUT_URL = 'https://example.org/'

    def setup() {
        CoreAuthProperties coreAuthPropertiesBean = new CoreAuthProperties()
        coreAuthPropertiesBean.defaultLogoutRedirectUri = 'http://localhost:8080/'

        defineBeans {
            coreAuthProperties(InstanceFactoryBean, coreAuthPropertiesBean, CoreAuthProperties)
        }
    }

    Closure doWithConfig() {{ config ->
        config.security.cas.logoutUrl = LOGOUT_URL
    }}

    def testLogoutDefaultAppUrlIsAbsolute() {
        setup:
        // need to save a reference to current session to prevent creation of a new session
        def session = getSession()

        when:
        controller.logout()

        then:
        session.isInvalid()
        response.redirectedUrl == "$LOGOUT_URL?url=${URLEncoder.encode('http://localhost:8080/','UTF-8')}"
    }

    def testLogoutAppUrlDisallowsExternalRedirect() {
        setup:
        def session = getSession()
        params.appUrl = 'https://test.org'

        when:
        controller.logout()

        then:
        session.isInvalid()
        response.redirectedUrl == "$LOGOUT_URL?url=${URLEncoder.encode('http://localhost:8080/','UTF-8')}"
    }

    def testLogoutAppUrlWithChildUri() {
        setup:
        def session = getSession()
        params.appUrl = 'http://localhost:8080/home/index'

        when:
        controller.logout()

        then:
        session.isInvalid()
        response.redirectedUrl == "$LOGOUT_URL?url=${URLEncoder.encode('http://localhost:8080/home/index','UTF-8')}"
    }

    def testLogoutAppUrlWithChildUriAndQueryFragment() {
        setup:
        def session = getSession()
        params.appUrl = 'http://localhost:8080/home/index?test#test'

        when:
        controller.logout()

        then:
        session.isInvalid()
        response.redirectedUrl == "$LOGOUT_URL?url=${URLEncoder.encode('http://localhost:8080/home/index?test#test','UTF-8')}"
    }

    def testLogoutAppUrlWithRelativeUri() {
        setup:
        def session = getSession()
        params.url = '/home/index'

        when:
        controller.logout()

        then:
        session.isInvalid()
        // This is missing the port number due to the way the MockServletRequest works
        response.redirectedUrl == "$LOGOUT_URL?url=${URLEncoder.encode('http://localhost/home/index','UTF-8')}"
    }

    def testLogoutAppUrlWithRelativeUriAndQueryFragment() {
        setup:
        def session = getSession()
        params.url = '/home/index?test#test'

        when:
        controller.logout()

        then:
        session.isInvalid()
        // This is missing the port number due to the way the MockServletRequest works
        response.redirectedUrl == "$LOGOUT_URL?url=${URLEncoder.encode('http://localhost/home/index?test#test','UTF-8')}"
    }

    def testLogoutAppUrlWithInvalidRelativeUri() {
        setup:
        def session = getSession()
        params.url = 'no-starting-slash'

        when:
        controller.logout()

        then:
        session.isInvalid()
        response.redirectedUrl == "$LOGOUT_URL?url=${URLEncoder.encode('http://localhost:8080/','UTF-8')}"
    }


    def testLogoutAppUrlWithInvalidSchemaRelativeUri() {
        setup:
        def session = getSession()
        params.url = '//example.org/home/index'

        when:
        controller.logout()

        then:
        session.isInvalid()
        response.redirectedUrl == "$LOGOUT_URL?url=${URLEncoder.encode('http://localhost:8080/','UTF-8')}"
    }
}
