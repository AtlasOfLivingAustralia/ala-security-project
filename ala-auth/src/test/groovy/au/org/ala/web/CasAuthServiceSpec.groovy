package au.org.ala.web

import au.org.ala.cas.util.AuthenticationCookieUtils
import au.org.ala.userdetails.UserDetailsClient
import org.grails.plugins.testing.GrailsMockHttpSession
import org.grails.web.servlet.DefaultGrailsApplicationAttributes
import org.grails.web.servlet.mvc.GrailsWebRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockServletContext
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.web.context.request.RequestContextHolder
import retrofit2.mock.Calls
import spock.lang.Specification

import jakarta.servlet.http.Cookie
import java.security.Principal

class CasAuthServiceSpec extends Specification {

    private static class PrincipalWithAttributes implements Principal {
        final String name
        final Map attributes

        PrincipalWithAttributes(String name, Map attributes) {
            this.name = name
            this.attributes = attributes
        }
    }

    def "test getUserId with empty cookie value"() {
        setup:
        def username = ''

        setupMockRequest(username)

        def userDetailsClient = Mock(UserDetailsClient)

        def service = new CasAuthService(userDetailsClient, false, 'https://example.org/')

        when:
        def userId = service.getUserId()

        then:

        0 * userDetailsClient.getUserDetails(username, true)
        userId == null
    }

    def "test getUserId with non-empty cookie value"() {
        setup:
        def username = 'foo@example.org'

        setupMockRequest(username)

        def userDetailsClient = Mock(UserDetailsClient)

        def service = new CasAuthService(userDetailsClient, false, 'https://example.org/')

        when:
        def userId = service.getUserId()

        then:

        1 * userDetailsClient.getUserDetails(username, true) >> Calls.response(new UserDetails(1, 'Foo', 'Bar', username, username, '1234', false, false, ['ROLE_USER'] as Set))
        userId == '1234'
    }

    private setupMockRequest(String username) {
        def servletContext = new MockServletContext()
        def attributes = new DefaultGrailsApplicationAttributes(servletContext)

        def session = new GrailsMockHttpSession()
        def request = MockMvcRequestBuilders.get('https://example.org/')
                .session(session)
                .cookie(new Cookie(AuthenticationCookieUtils.ALA_AUTH_COOKIE, username))
                .buildRequest(servletContext)
        request.setUserPrincipal(new PrincipalWithAttributes(username, [email: username]))
        def response = new MockHttpServletResponse()

        // GWR users the Spring Context so could be fragile?
        RequestContextHolder.setRequestAttributes(new GrailsWebRequest(request, response, attributes))
    }
}
