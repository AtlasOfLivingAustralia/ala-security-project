package au.org.ala.web

import grails.testing.web.controllers.ControllerUnitTest
import spock.lang.Specification

class LogoutControllerSpec extends Specification implements ControllerUnitTest<LogoutController> {

    static LOGOUT_URL = 'https://example.org/'

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
        params.appUrl = 'https://example.org'

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
}
