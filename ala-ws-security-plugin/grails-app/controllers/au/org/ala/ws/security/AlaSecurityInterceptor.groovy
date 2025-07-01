package au.org.ala.ws.security


import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.org.ala.grails.AnnotationMatcher
import au.ala.org.ws.security.filter.RequireApiKeyFilter
import au.org.ala.ws.security.profile.AlaApiUserProfile
import com.nimbusds.oauth2.sdk.Scope
import grails.core.GrailsApplication
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.apache.commons.lang3.tuple.Pair
import org.pac4j.core.adapter.FrameworkAdapter
import org.pac4j.core.client.DirectClient
import org.pac4j.core.config.Config
import org.pac4j.core.context.CallContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.UserProfile
import org.pac4j.http.profile.IpProfile
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.jwt.profile.JwtProfile
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials
import org.pac4j.oidc.profile.OidcProfile
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.http.HttpStatus

import javax.annotation.PostConstruct

@CompileStatic
@Slf4j
@EnableConfigurationProperties(JwtProperties)
class AlaSecurityInterceptor {

    @Autowired(required = false)
    @Qualifier('alaClient')
    List<DirectClient> clientList

    @Autowired(required = false)
    Config config

    @Autowired(required = false)
    RequireApiKeyFilter requireApiKeyFilter

    @Autowired(required = false)
    JwtProperties jwtProperties

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

        if (effectiveAnnotation && !skipAnnotation && clientList) {

            boolean authenticated = false
            boolean authorised = true
            boolean scopesAuthorised
            boolean rolesAuthorised
            boolean customFilterAuthorised

            try {

                def params = new JEEFrameworkParameters(request, response)

                FrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config)
                final WebContext context = config.getWebContextFactory().newContext(params)
                final SessionStore sessionStore = config.sessionStoreFactory.newSessionStore(params)
                final callContext = new CallContext(context, sessionStore, config.profileManagerFactory)

                Optional<Pair<DirectClient, Credentials>> optCredentials = getCredentials(clientList, callContext)
                Optional<UserProfile> optProfile = Optional.empty()

                if (optCredentials.isPresent()) {

                    authenticated = true
                    def pair = optCredentials.get()
                    def client = pair.left
                    Credentials credentials = pair.right
                    def scopes, roles

                    String[] requiredScopes = effectiveAnnotation.scopes() + scopesFromProperty(effectiveAnnotation.scopesFromProperty())
                    String[] requiredRoles = effectiveAnnotation.roles()

                    if (requiredScopes) {

                        if (credentials instanceof OidcCredentials) {

                            scopes = (credentials as OidcCredentials).toAccessToken().scope

                            scopesAuthorised = scopesAllowed(scopes, effectiveAnnotation)

                            if (!scopesAuthorised && !effectiveAnnotation.eitherRolesOrScopes()) {
                                log.info "access_token scopes '${scopes}' is missing required scopes ${requiredScopes}"
                            }
                        } else if (credentials instanceof TokenCredentials) {

                            def profile = credentials.userProfile

                            // if we have a JWT profile from the authenticator we can extract the scopes from the token
                            // without having to load the full profile via the profile creator.
                            if (profile instanceof JwtProfile && jwtProperties.scopesFromAccessToken) {

                                scopes = (profile as JwtProfile).getAttribute(OidcConfiguration.SCOPE) ?: (profile as JwtProfile).getAuthenticationAttribute(OidcConfiguration.SCOPE)

                                scopesAuthorised = scopesAllowed(scopes, effectiveAnnotation)

                                if (!scopesAuthorised && !effectiveAnnotation.eitherRolesOrScopes()) {
                                    log.info "access_token scopes '${scopes}' is missing required scopes ${requiredScopes}"
                                }
                            } else {
                                // we don't have a JWT, so we need to get the full profile from the client
                                // ie via token introspection. This will allow us to get the scopes.
                                optProfile = client.getUserProfile(callContext, credentials)
                                profile = optProfile.orElse(null)
                                if (profile instanceof OidcProfile) {
                                    scopes = (profile as OidcProfile).getAccessToken().scope

                                    scopesAuthorised = scopesAllowed(scopes, effectiveAnnotation)

                                    if (!scopesAuthorised && !effectiveAnnotation.eitherRolesOrScopes()) {
                                        log.info "access_token scopes '${scopes}' is missing required scopes ${requiredScopes}"
                                    }
                                } else if (!(profile instanceof IpProfile || profile instanceof AlaApiUserProfile)) {
                                    // ip address and apikey user profiles are not required to have scopes
                                    log.info "Couldn't extract scopes from profile ${profile}"
                                    scopesAuthorised = false
                                }

                            }
                        }
                    }

                    if (effectiveAnnotation.useCustomFilter()) {

                            if (requireApiKeyFilter) {
                                customFilterAuthorised = requireApiKeyFilter.isAllowed(effectiveAnnotation, this)
                            } else {
                                log.error "useCustomFilter is true but no filter is available"
                                customFilterAuthorised = false
                            }
                    } else {
                        customFilterAuthorised = true
                    }

                    if (optProfile.isEmpty()) {
                        optProfile = client.getUserProfile(callContext, credentials)
                    }

                    if (optProfile.isPresent()) {

                        UserProfile userProfile = optProfile.get()

                        ProfileManager profileManager = config.profileManagerFactory.apply(context, sessionStore)
                        profileManager.setConfig(config)

                        profileManager.save(
                                client.getSaveProfileInSession(context, userProfile),
                                userProfile,
                                client.isMultiProfile(context, userProfile)
                        )

                        roles = userProfile.roles

                        rolesAuthorised = rolesAllowed(roles, effectiveAnnotation)

                        if (!rolesAuthorised && !effectiveAnnotation.eitherRolesOrScopes()) {
                            log.info "user profile roles '${roles}' is missing required scopes ${requiredRoles}"
                        }
                    } else if (effectiveAnnotation.roles()) {

                        rolesAuthorised = false
                        log.info "no user profile available missing roles"
                    }

                    if (effectiveAnnotation.eitherRolesOrScopes()) {
                        authorised = scopesAuthorised || rolesAuthorised && customFilterAuthorised
                        if (!authorised) {
                            log.info "access_token scopes '${scopes}' is missing required scopes ${requiredScopes}"
                            log.info "user profile roles '${roles}' is missing required scopes ${requiredRoles}"
                            log.info "eitherRolesOrScopes is true but neither scopes nor roles are authorised"
                        }
                    } else {
                        authorised = scopesAuthorised && rolesAuthorised && customFilterAuthorised
                    }
                } else {

                    log.info "no auth credentials found"
                    authorised = false
                }

            } catch (CredentialsException e) {

                log.info("authentication failed invalid credentials", e)
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

    private static final String[] EMPTY_STRING_ARRAY = new String[0]

    private String[] scopesFromProperty(String[] propertyScopes) {
        def retVal = propertyScopes?.collectMany {
            grailsApplication.config.getProperty(it, List<String>, [])
        }

        String[] retArr = retVal?.toArray(new String[retVal.size()])
        return  retArr ?: EMPTY_STRING_ARRAY
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

    boolean scopesAllowed(Object scopeObj, RequireApiKey effectiveAnnotation) {

        if (!scopeObj || !effectiveAnnotation) {
            return true
        }

        String[] requiredScopes = effectiveAnnotation.scopes() + scopesFromProperty(effectiveAnnotation.scopesFromProperty())

        if (requiredScopes.length == 0) {
            return true
        }

        if (effectiveAnnotation.anyScope()) {
            return requiredScopes.any { scopeContains(scopeObj, it) }
        } else {
            return requiredScopes.every { scopeContains(scopeObj, it) }
        }
    }

    boolean rolesAllowed(Set<String> roles, RequireApiKey effectiveAnnotation) {

        if (!effectiveAnnotation) {
            return true
        }

        String[] requiredRoles = effectiveAnnotation.roles()

        if (requiredRoles.length == 0) {
            return true
        }

        if (effectiveAnnotation.anyRole()) {
            return requiredRoles.any { roles.contains(it) }
        } else {
            return requiredRoles.every { roles.contains(it) }
        }
    }

    boolean scopeContains(Object scopeObj, String requiredScope) {
        if (scopeObj instanceof String) {
            return scopeObj.trim().split(' ').any {it == requiredScope }
        } else if (scopeObj instanceof Scope) {
            return scopeObj.contains(requiredScope)
        } else if (scopeObj instanceof Collection) {
            return scopeObj.contains(requiredScope)
        } else if (scopeObj instanceof String[]) {
            return scopeObj.contains(requiredScope)
        } else {
            return false
        }
    }

    // This is a condensed version of the pac4j DefaultSecurityLogic, we don't need the full logic here
    // as we are only interested in the credentials and scopes.
    Optional<Pair<DirectClient, Credentials>> getCredentials(List<DirectClient> clients, CallContext context) {
        try {
            for (DirectClient client : clients) {
                Credentials credentials = client.getCredentials(context).orElse(null)
                credentials = (Credentials)client.validateCredentials(context, credentials).orElse(null)
                if (credentials != null && credentials.isForAuthentication()) {
                    return Optional.of(Pair.of(client, credentials))
                }
            }
        } catch (CredentialsException e) {
            log.info("Failed to retrieve credentials: {}", e.getMessage())
            log.debug("Failed to retrieve credentials", e)
        }
        return Optional.empty()
    }
}
