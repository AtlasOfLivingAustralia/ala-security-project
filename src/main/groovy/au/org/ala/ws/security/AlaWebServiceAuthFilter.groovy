package au.org.ala.ws.security

import org.pac4j.core.config.Config
import org.pac4j.core.profile.UserProfile

import org.springframework.beans.factory.annotation.Autowired
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

    @Autowired
    JwtProperties jwtProperties

    @Autowired(required = false)
    Config config

//    @Inject
    AlaWebServiceAuthUtils alaWebServiceAuthUtils

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Optional<UserProfile> userProfile = Optional.empty()

        if (jwtProperties.enabled) {
            userProfile = alaWebServiceAuthUtils.oidcInterceptor(request, response)
        }

        if (!userProfile.isPresent() && jwtProperties.fallbackToLegacyBehaviour) {
            alaWebServiceAuthUtils.legacyApiKeyInterceptor(request, response)
        }

        userProfile.ifPresent this.&setAuthenticatedUserAsPrincipal

        chain.doFilter(request, response);
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