package au.org.ala.web

import grails.web.mapping.LinkGenerator
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.util.Pac4jConstants
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.oidc.profile.OidcProfile
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import spock.lang.Specification

class Pac4jAuthServiceSpec extends Specification {

    def "test role prefix"(String rolePrefix, String inputRole, String expectedRole) {
        setup:
        def config = Stub(Config)
        def request = new MockHttpServletRequest()
        def response = new MockHttpServletResponse()
        def provider = new Pac4jContextProvider() {
            @Override
            WebContext webContext() {
                return JEEContextFactory.INSTANCE.newContext(request, response)
            }
        }
        def sessionStore = Stub(SessionStore)
        def linkGenerator = Stub(LinkGenerator)
        def service = new Pac4jAuthService(config, provider, sessionStore, linkGenerator, rolePrefix, true)

        def profile = new OidcProfile()
        profile.addAttribute(Pac4jAuthService.ATTR_ROLE, inputRole)
        profile.addRole(inputRole)
        profile.tokenExpirationAdvance = -1
        sessionStore.get(_, Pac4jConstants.USER_PROFILES) >> Optional.of(['oidc': profile])

        when:
        def roles = service.userRoles

        then:

        roles.contains(expectedRole)

        where:
        rolePrefix | inputRole | expectedRole
        "" | "ROLE_USER" | "ROLE_USER"
        "ROLE_" | "user" | "ROLE_USER"
    }

}
