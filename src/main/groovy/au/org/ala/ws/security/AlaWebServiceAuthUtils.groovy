package au.org.ala.ws.security

import groovy.json.JsonSlurper
import groovy.util.logging.Slf4j
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.UserProfile
import org.pac4j.core.util.FindBest
import org.pac4j.http.client.direct.DirectBearerAuthClient
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
    DirectBearerAuthClient bearerClient // Could be any DirectClient?

    @Autowired(required = false)
    DirectBearerAuthClient bearerOidcClient // Could be any DirectClient?

    @Autowired(required = false)
    Config config

    AlaWebServiceAuthUtils() {}

    /**
     * Validate a JWT Bearer token.
     *
     * @return UserProfile if the request is authorised
     */
    Optional<UserProfile> jwtApiKeyInterceptor(HttpServletRequest request, HttpServletResponse response) {

        WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)

        ProfileManager profileManager = new ProfileManager(context, config.sessionStore)
        profileManager.setConfig(config)

        Optional<Credentials> accessCredentials = bearerClient.getCredentials(context, config.sessionStore)
        if (accessCredentials.present) {

            Optional<UserProfile> accessProfile = bearerClient.getUserProfile(accessCredentials.get(), context, config.sessionStore)
            if (accessProfile.present) {

                UserProfile userProfile = accessProfile.get()

                if (jwtProperties.requiredScopes.every {userProfile.permissions.contains(it) }) {

                    if (!jwtProperties.userProfileFromAccessToken) {

                        Optional<Credentials> idCredentials = bearerOidcClient.getCredentials(context, config.sessionStore)
                        if (idCredentials.present) {

                            Optional<UserProfile> idProfile = bearerOidcClient.getUserProfile(idCredentials.get(), context, config.sessionStore)
                            if (idProfile.present) {

                                userProfile = idProfile.get()

                                profileManager.save(
                                        bearerOidcClient.getSaveProfileInSession(context, userProfile),
                                        userProfile,
                                        bearerOidcClient.isMultiProfile(context, userProfile)
                                )
                            }
                        }
                    }

                    return Optional.of(userProfile)

                } else {

                    log.info "access_token scopes '${userProfile.permissions}' is missing required scopes ${jwtProperties.requiredScopes}"
                }

            } else {

                log.info "Bearer access token present but no user info found: ${accessCredentials}"
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