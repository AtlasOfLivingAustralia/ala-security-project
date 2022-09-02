package au.org.ala.ws.security

import au.org.ala.ws.security.client.AlaAuthClient
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.UserProfile
import org.pac4j.core.util.FindBest
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.oidc.credentials.OidcCredentials
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

import javax.inject.Inject
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Spring based Webservice Authentication Filter. This filter supports 3 modes of authentication:
 * 1) JSON Web tokens
 * 2) Legacy API keys using ALA's apikey app
 * 3) Whitelist IP
 */
class AlaWebServiceAuthFilter extends OncePerRequestFilter {

    @Autowired(required = false)
    Config config

    @Autowired(required = false)
    AlaAuthClient alaAuthClient // Could be any DirectClient?

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        boolean authenticated = false
        boolean authorised = true

        try {

            WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)

            Optional<Credentials> optCredentials = alaAuthClient.getCredentials(context, config.sessionStore)
            if (optCredentials.isPresent()) {

                authenticated = true
                Credentials credentials = optCredentials.get()

                    Optional<UserProfile> optProfile = alaAuthClient.getUserProfile(credentials, context, config.sessionStore)
                    if (optProfile.isPresent()) {

                        UserProfile userProfile = optProfile.get()

                        setAuthenticatedUserAsPrincipal(userProfile)

                        ProfileManager profileManager = new ProfileManager(context, config.sessionStore)
                        profileManager.setConfig(config)

                        profileManager.save(
                                alaAuthClient.getSaveProfileInSession(context, userProfile),
                                userProfile,
                                alaAuthClient.isMultiProfile(context, userProfile)
                        )
                    }
                }


        } catch (CredentialsException e) {

            log.info "authentication failed invalid credentials", e
            authenticated = false
        }

        if (!authenticated) {

            response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase())
            return
        }

        if (!authorised) {

            response.sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase())
            return
        }

        chain.doFilter(request, response)
    }


    private void setAuthenticatedUserAsPrincipal(UserProfile userProfile) {

        SecurityContext securityContext = SecurityContextHolder.getContext()
        List<String> credentials = []
        List<GrantedAuthority> authorities = []

        userProfile.roles.forEach {s -> authorities.add(new SimpleGrantedAuthority(s)) }

        AlaUser alaUser = new AlaUser()
        alaUser.email = userProfile.getAttribute('email')
        alaUser.roles = userProfile.roles
        alaUser.attributes = userProfile.attributes
        alaUser.firstName = userProfile.getAttribute('given_name')
        alaUser.lastName = userProfile.getAttribute('family_name')

        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
                alaUser, credentials, authorities)
        token.setAuthenticated(true)
        securityContext.setAuthentication(token)
    }
}