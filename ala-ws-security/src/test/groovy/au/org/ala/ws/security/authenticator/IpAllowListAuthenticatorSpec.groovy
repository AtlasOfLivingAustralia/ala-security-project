package au.org.ala.ws.security.authenticator

import org.pac4j.core.context.CallContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.exception.CredentialsException
import org.pac4j.jee.context.JEEContext
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.jee.context.session.JEESessionStoreFactory
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import spock.lang.Specification
import spock.lang.Unroll

class IpAllowListAuthenticatorSpec extends Specification {

    def allowedAddrs = [
            '8.8.8.8',
            '8.8.4.4',
            '1:2:3:4:5:6:7:8',
            '192.168.1.0/24',
            '1111:222::/64',
            '1.*.1-3.1-4'
    ]

    def setup() {

    }

    @Unroll
    def 'valid ip address #ip is allowed'(String ip) {
        setup:
        def authenticator = new IpAllowListAuthenticator()
        def credentials = new TokenCredentials(ip)

        authenticator.setIpAllowList(allowedAddrs)

        MockHttpServletRequest request = new MockHttpServletRequest()
        MockHttpServletResponse response = new MockHttpServletResponse()

        WebContext context = new JEEContext(request, response)
        SessionStore store = JEESessionStoreFactory.INSTANCE.newSessionStore(new JEEFrameworkParameters(request, response))

        when:
        authenticator.validate(new CallContext(context, store), credentials)

        then:
        notThrown(CredentialsException)

        where:
        ip << [
            '127.0.0.1',
            '1.1.1.1',
            '1.127.2.3',
            '8.8.8.8',
            '192.168.1.1',
            '1:2:3:4:5:6:7:8',
            '1111:222:0:0:0:8a2e:370:7334'
        ]
    }

    @Unroll
    def 'invalid ip address #ip is denied'(String ip) {
        setup:
        def authenticator = new IpAllowListAuthenticator()
        def credentials = new TokenCredentials(ip)

        authenticator.setIpAllowList(allowedAddrs)

        MockHttpServletRequest request = new MockHttpServletRequest()
        MockHttpServletResponse response = new MockHttpServletResponse()

        WebContext context = new JEEContext(request, response)
        SessionStore store = JEESessionStoreFactory.INSTANCE.newSessionStore(new JEEFrameworkParameters(request, response))

        when:
        authenticator.validate(new CallContext(context, store), credentials)

        then:
        thrown(CredentialsException)

        where:
        ip << ['2.2.2.2', '1.127.1.5']
    }
}
