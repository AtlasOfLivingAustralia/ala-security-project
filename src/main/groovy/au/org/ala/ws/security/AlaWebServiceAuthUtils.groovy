package au.org.ala.ws.security

import groovy.json.JsonSlurper
import groovy.util.logging.Slf4j
import org.pac4j.core.authorization.generator.AuthorizationGenerator
import org.pac4j.core.client.DirectClient
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.UserProfile
import org.pac4j.core.util.FindBest
import org.pac4j.jee.context.JEEContextFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Spring based Webservice Authentication Filter. This filter supports 3 modes of authentication:
 * 1) JSON Web tokens
 * 2) Legacy API keys using ALA's apikey app
 * 3) Whitelist IP
 */
@Component
@Slf4j
class AlaWebServiceAuthUtils {

    static final List<String> LOOPBACK_ADDRESSES = [ '127.0.0.1',
                                                     '0:0:0:0:0:0:0:1', // IP v6
                                                     '::1' ]            // IP v6 short form

    @Value('${security.apikey.check.serviceUrl:}')
    String apiKeyServiceUrl

    @Value('${security.apikey.header.override:apiKey}')
    String apiKeyHeaderName = "apiKey"

    @Value('#{"${security.apikey.ip.whitelist:}".split(",")}')
    List<String> whitelistOfips = []

    @Autowired
    JwtProperties jwtProperties

    @Autowired(required = false)
    DirectClient directClient // Could be any DirectClient?

    @Autowired
    JwtAuthenticator jwtAuthenticator

    @Autowired
    AuthorizationGenerator attributeAuthorizationGenerator

    @Autowired(required = false)
    Config config

    AlaWebServiceAuthUtils() {}

    Optional<AlaUser> getAuthenticatedUser(HttpServletRequest request, HttpServletResponse response) {

        Optional<UserProfile> userProfile = oidcInterceptor(request, response)

        if (!userProfile.isPresent() && jwtProperties.fallbackToLegacyBehaviour) {

            userProfile = legacyApiKeyInterceptor(request, response)
        }


    }

    /**
     * Validate a JWT Bearer token.
     *
     * @return UserProfile if the request is authorised
     */
    Optional<UserProfile> oidcInterceptor(HttpServletRequest request, HttpServletResponse response) {

        WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)

        ProfileManager profileManager = new ProfileManager(context, config.sessionStore)
        profileManager.setConfig(config)

        Optional<Credentials> optCredentials = directClient.getCredentials(context, config.sessionStore)
        if (optCredentials.present) {

            TokenCredentials credentials = optCredentials.get()

            // we will need to validate the access_token if we are checking for required scopes (scope claims of the access_token)
            if (jwtProperties.requiredScopes) {

                TokenCredentials accessCredentials = new TokenCredentials(credentials.token)
                jwtAuthenticator.validate(accessCredentials, context, config.sessionStore)

                Optional<UserProfile> optAccessProfile = Optional.of(accessCredentials.userProfile)

                if (accessCredentials.userProfile && attributeAuthorizationGenerator) {

                    // retrieve authorisation properties from the attributes (claims)
                    // this will populate the UserProfile::permissions using the JwtProperties::permissionAttributes from the claims
                    optAccessProfile = attributeAuthorizationGenerator.generate(context, config.sessionStore, accessCredentials.userProfile)
                }

                if (optAccessProfile.present) {

                    Set<String> scopes = optAccessProfile.get().permissions

                    // checked that the profile permissions contains all required scopes
                    if (!jwtProperties.requiredScopes.every {requiredScope -> scopes.any { scope -> scope.split(/\s+/).contains(requiredScope) } }) {

                        log.info "access_token scopes '${scopes}' is missing required scopes ${jwtProperties.requiredScopes}"
                        throw new CredentialsException("access_token scopes '${scopes}' is missing required scopes ${jwtProperties.requiredScopes}")
                    }

                } else {

                    log.info "Bearer access token present but no user info found: ${credentials}"
                    throw new CredentialsException("Bearer access token present but no user info found: ${credentials}")
                }
            }

            Optional<UserProfile> optUserProfile = directClient.getUserProfile(credentials, context, config.sessionStore)
            if (optUserProfile.isPresent()) {

                UserProfile userProfile = optUserProfile.get()

                profileManager.save(
                        directClient.getSaveProfileInSession(context, userProfile),
                        userProfile,
                        directClient.isMultiProfile(context, userProfile)
                )

                return Optional.of(userProfile)

            } else {

                log.info "Bearer access token present but no user info found"
                throw new CredentialsException("Bearer access token present but no user info found: ${credentials}")
            }
        }

        return Optional.empty()
    }

    boolean legacyApiKeyInterceptor(HttpServletRequest request, HttpServletResponse response) {

        List<String> whiteList = buildWhiteList()
        String clientIp = getClientIP(request)

        if (!clientIp in whiteList) {

            boolean keyOk = checkApiKey(request.getHeader(apiKeyHeaderName)).valid

            log.debug("IP ${clientIp} is not ok. Key ${keyOk ? 'is' : 'is not'} ok.")

            if (!keyOk) {

                log.warn "No valid api key for ${request.contextPath}"
                return false
            }

        } else {

            log.debug("IP ${clientIp} is exempt from the API Key check. Authorising.");
        }

        return true
    }

    String getClientIP(HttpServletRequest request) {

        // External requests may be proxied by Apache, which uses X-Forwarded-For to identify the original IP.
        String ip = request.getHeader("X-Forwarded-For")

        if (ip == null || ip in LOOPBACK_ADDRESSES) {
            // don't accept localhost from the X-Forwarded-For header, since it can be easily spoofed.
            ip = request.getRemoteHost()
        }

        return ip
    }

    /**
     * Build white list
     * @return
     */
    List<String> buildWhiteList() {

        List<String> whiteList = [] + LOOPBACK_ADDRESSES // allow calls from localhost to make testing easier

        if (!whitelistOfips.isEmpty()) {
            whiteList += whitelistOfips
        }

        return whiteList
    }

    Map checkApiKey(String apiKey) {

        Map response

        try {

            URLConnection conn = new URL("${apiKeyServiceUrl}${apiKey}").openConnection()

            if (conn.responseCode == 200) {

                response = new JsonSlurper().parseText(conn.content.text as String)

                if (!response.valid) {
                    log.info "Rejected - " + (apiKey ? "using key ${apiKey}" : "no key present")
                }

                return response

            } else {
                log.info "Rejected - " + (apiKey ? "using key ${apiKey}" : "no key present")
            }

        } catch (Exception e) {
            log.error "Failed to lookup key ${apiKey}", e
        }

        return [ valid: false ]
    }
}