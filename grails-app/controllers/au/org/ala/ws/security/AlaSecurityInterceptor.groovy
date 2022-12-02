package au.org.ala.ws.security


import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.org.ala.grails.AnnotationMatcher
import au.org.ala.ws.security.client.AlaAuthClient
import grails.core.GrailsApplication
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
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
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.http.HttpStatus

import javax.annotation.PostConstruct

@CompileStatic
@Slf4j
@EnableConfigurationProperties(JwtProperties)
class AlaSecurityInterceptor {

    @Autowired(required = false)
    AlaAuthClient alaAuthClient // Could be any DirectClient?

    @Autowired(required = false)
    Config config

    GrailsApplication grailsApplication

    AlaSecurityInterceptor() {
//        matchAll()
    }

    @PostConstruct
    def init() {
        AnnotationMatcher.matchAnnotation(this, grailsApplication, RequireApiKey)
    }

    /**
     * Executed before a matched action
     *
     * @return Whether the action should continue and execute
     */
    boolean before() {

        def matchResult = AnnotationMatcher.getAnnotation(grailsApplication, controllerNamespace, controllerName, actionName, RequireApiKey, SkipApiKeyCheck)
        def effectiveAnnotation = matchResult.effectiveAnnotation()
        def skipAnnotation = matchResult.overrideAnnotation

        if (effectiveAnnotation && !skipAnnotation && alaAuthClient) {

            boolean authenticated = false
            boolean authorised = true

            try {

                WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)

                Optional<Credentials> optCredentials = alaAuthClient.getCredentials(context, config.sessionStore)
                if (optCredentials.isPresent()) {

                    authenticated = true
                    Credentials credentials = optCredentials.get()

                    String[] requiredScopes = effectiveAnnotation.scopes()
                    if (requiredScopes) {

                        if (credentials instanceof OidcCredentials) {

                            OidcCredentials oidcCredentials = credentials

                            authorised = requiredScopes.every { String requiredScope ->
                                oidcCredentials.accessToken.scope.contains(requiredScope)
                            }

                            if (!authorised) {
                                log.info "access_token scopes '${oidcCredentials.accessToken.scope}' is missing required scopes ${requiredScopes}"
                            }
                        }
                    }

                    if (authorised) {

                        Optional<UserProfile> optProfile = alaAuthClient.getUserProfile(credentials, context, config.sessionStore)
                        if (optProfile.isPresent()) {

                            UserProfile userProfile = optProfile.get()

                            ProfileManager profileManager = new ProfileManager(context, config.sessionStore)
                            profileManager.setConfig(config)

                            profileManager.save(
                                    alaAuthClient.getSaveProfileInSession(context, userProfile),
                                    userProfile,
                                    alaAuthClient.isMultiProfile(context, userProfile)
                            )

                            String[] requiredRoles = effectiveAnnotation.roles()

                            if (requiredRoles) {
                                authorised = requiredRoles.every() { String requiredRole -> userProfile.roles.contains(requiredRole) }

                                if (!authorised) {
                                    log.info "user profile roles '${userProfile.roles}' is missing required scopes ${requiredRoles}"
                                }
                            }
                        } else if (effectiveAnnotation.roles()) {

                            authorised = false
                            log.info "no user profile available missing roles"
                        }
                    }
                } else {

                    log.info "no auth credentials found"
                    authorised = false
                }

            } catch (CredentialsException e) {

                log.info "authentication failed invalid credentials", e
                authenticated = false
            }

            if (!authenticated) {

                response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase())
                return false
            }

            if (!authorised) {

                response.sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase())
                return false
            }
        }

        return true
    }

    /**
     * Executed after the action executes but prior to view rendering
     *
     * @return True if view rendering should continue, false otherwise
     */
    boolean after() { true }

    /**
     * Executed after view rendering completes
     */
    void afterView() {}
}
