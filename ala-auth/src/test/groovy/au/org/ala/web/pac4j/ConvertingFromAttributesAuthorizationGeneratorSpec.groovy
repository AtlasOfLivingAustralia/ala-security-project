package au.org.ala.web.pac4j

import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.session.JEESessionStoreFactory
import org.pac4j.oidc.profile.OidcProfile
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import spock.lang.Specification

class ConvertingFromAttributesAuthorizationGeneratorSpec extends Specification {

    def "test role conversion"(String rolePrefix, boolean convertRolesToUpperCase, String result) {
        setup:

        def request  = new MockHttpServletRequest()
        def response = new MockHttpServletResponse()
        def sessionStore = JEESessionStoreFactory.INSTANCE.newSessionStore()
        def context = JEEContextFactory.INSTANCE.newContext(request, response)

        def authGen = new ConvertingFromAttributesAuthorizationGenerator(['role:ala'], ['scp'], rolePrefix, convertRolesToUpperCase)

        def profile = new OidcProfile()
        profile.addAttribute('role:ala', 'user')

        when:
        def newProfile = authGen.generate(context, sessionStore, profile)

        then:
        newProfile.isPresent()
        newProfile.get().roles.contains(result)

        where:
        rolePrefix  | convertRolesToUpperCase | result
        ''          | false                   | 'user'
        ''          | true                    | 'USER'
        'role_'     | false                   | 'role_user'
        'role_'     | true                    | 'ROLE_USER'

    }
}
