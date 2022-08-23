package au.org.ala.ws.security

import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.org.ala.grails.AnnotationMatcher
import au.org.ala.ws.security.service.ApiKeyService
import grails.core.GrailsApplication
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.util.FindBest
import org.pac4j.http.client.direct.DirectBearerAuthClient
import org.pac4j.jee.context.JEEContextFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.http.HttpStatus

import javax.annotation.PostConstruct
import javax.servlet.http.HttpServletRequest

@CompileStatic
@Slf4j
@EnableConfigurationProperties(JwtProperties)
class ApiKeyInterceptor {
    ApiKeyService apiKeyService

    static final int STATUS_UNAUTHORISED = 403
    static final String API_KEY_HEADER_NAME = "apiKey"
    static final List<String> LOOPBACK_ADDRESSES = ["127.0.0.1",
                                                    "0:0:0:0:0:0:0:1", // IP v6
                                                    "::1"] // IP v6 short form

    @Autowired
    JwtProperties jwtProperties
    @Autowired(required = false)
    DirectBearerAuthClient bearerAuthClient // Could be any DirectClient?
    @Autowired(required = false)
    Config config
    GrailsApplication grailsApplication

    ApiKeyInterceptor() {
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

        def result = true
        if (effectiveAnnotation && !skipAnnotation) {
            if (jwtProperties.enabled) {
                def fallbackToLegacy = jwtProperties.fallbackToLegacyBehaviour
                result = jwtApiKeyInterceptor(effectiveAnnotation, fallbackToLegacy)
            } else {
                result = legacyApiKeyInterceptor()
            }
        }
        return result
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

    /**
     * Validate a JWT Bearer token instead of the API key.
     * @param requireApiKey The RequireApiKey annotation
     * @param fallbackToLegacy Whether to fall back to legacy API keys if the JWT is not present.
     * @return true if the request is authorised
     */
    boolean jwtApiKeyInterceptor(RequireApiKey requireApiKey, boolean fallbackToLegacy) {
        def result = false

        def context = context()
        ProfileManager profileManager = new ProfileManager(context, config.sessionStore)
        profileManager.setConfig(config)

        def credentials = bearerAuthClient.getCredentials(context, config.sessionStore)
        if (credentials.isPresent()) {
            def profile = bearerAuthClient.getUserProfile(credentials.get(), context, config.sessionStore)
            if (profile.isPresent()) {
                def userProfile = profile.get()
                profileManager.save(
                        bearerAuthClient.getSaveProfileInSession(context, userProfile),
                        userProfile,
                        bearerAuthClient.isMultiProfile(context, userProfile)
                )

                result = true

                if (result && requireApiKey.roles()) {
                    def roles = userProfile.roles
                    result = requireApiKey.roles().every() {
                        roles.contains(it)
                    }
                }

                def requiredScopes = requireApiKey.scopes() + jwtProperties.requiredScopes
                if (result && requiredScopes) {
                    def scope = userProfile.permissions //attributes['scope'] as List<String>
                    result = requiredScopes.every {
                        scope.contains(it)
                    }
                }

            } else {
                log.info("Bearer token present but no user info found: {}", credentials)
                result = false
            }

            if (!result) {
                response.status = STATUS_UNAUTHORISED
                response.sendError(STATUS_UNAUTHORISED, "Forbidden")
            }
        } else if (fallbackToLegacy) {
            result = legacyApiKeyInterceptor()
        } else {
            response.status = HttpStatus.UNAUTHORIZED.value()
            response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase())
            result = false
        }
        return result
    }

    private WebContext context() {
        final WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)
        return context
    }

    boolean legacyApiKeyInterceptor() {
        List<String> whiteList = buildWhiteList()
        String clientIp = getClientIP(request)
        boolean ipOk = checkClientIp(clientIp, whiteList)
        def result = true
        if (!ipOk) {
            String headerName = grailsApplication.config.getProperty('security.apikey.header.override', API_KEY_HEADER_NAME)
            List<String> otherHeaderNames = grailsApplication.config.getProperty('security.apikey.header.alternatives', List, [])
            def apikey = request.getHeader(headerName) ?: otherHeaderNames.findResult { name -> request.getHeader(name.toString()) }
            boolean keyOk = apiKeyService.checkApiKey(apikey).valid
            log.debug "IP ${clientIp} ${ipOk ? 'is' : 'is not'} ok. Key ${keyOk ? 'is' : 'is not'} ok."

            if (!keyOk) {
                log.warn(ipOk ? "No valid api key for ${controllerName}/${actionName}" :
                        "Non-authorised IP address - ${clientIp}")
                response.status = STATUS_UNAUTHORISED
                response.sendError(STATUS_UNAUTHORISED, "Forbidden")
                result = false
            }
        } else {
            log.debug("IP ${clientIp} is exempt from the API Key check. Authorising.")
        }
        return result
    }

    /**
     * Client IP passes if it is in the whitelist
     * @param clientIp
     * @return
     */
    def checkClientIp(clientIp, List<String> whiteList) {
        whiteList.contains(clientIp)
    }

    List<String> buildWhiteList() {
        List<String> whiteList = []
        whiteList.addAll(LOOPBACK_ADDRESSES) // allow calls from localhost to make testing easier
        String config = grailsApplication.config.getProperty('security.apikey.ip.whitelist')
        if (config) {
            whiteList.addAll(config.split(',').collect({ String s -> s.trim() }))
        }
        log.debug('{}', whiteList)
        return whiteList
    }

    def getClientIP(HttpServletRequest request) {
        // External requests may be proxied by Apache, which uses X-Forwarded-For to identify the original IP.
        String ip = request.getHeader("X-Forwarded-For")
        if (!ip || LOOPBACK_ADDRESSES.contains(ip)) {
            // don't accept localhost from the X-Forwarded-For header, since it can be easily spoofed.
            ip = request.getRemoteHost()
        }
        return ip
    }

}
