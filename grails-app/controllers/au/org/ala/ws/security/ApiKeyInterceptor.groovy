package au.org.ala.ws.security

import au.ala.org.ws.security.AuthenticatedUser
import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.org.ala.ws.security.service.JwtCheckService
import au.org.ala.ws.security.service.LegacyApiKeyService
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Value

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@CompileStatic
@Slf4j
class ApiKeyInterceptor {

    @Value('${api.legacy.enabled:false}')
    Boolean legacyApiKeysEnabled

    @Value('${api.jwt.enabled:true}')
    Boolean jwtApiKeysEnabled

    @Value('${api.whitelist.enabled:false}')
    Boolean whitelistEnabled

    JwtCheckService jwtCheckService
    LegacyApiKeyService legacyApiKeyService

    static final String API_KEY_HEADER_NAME = "apiKey"
    static final String AUTHORIZATION_HEADER_NAME = "Authorization"
    static final List<String> LOOPBACK_ADDRESSES = ["127.0.0.1",
                                                    "0:0:0:0:0:0:0:1", // IP v6
                                                    "::1"] // IP v6 short form

    ApiKeyInterceptor() {
        matchAll()
    }

    /**
     * Executed before a matched action
     *
     * @return Whether the action should continue and execute
     */
    boolean before() {

        String headerName = grailsApplication.config.navigate('security', 'apikey', 'header', 'override') ?: API_KEY_HEADER_NAME
        def controller = grailsApplication.getArtefactByLogicalPropertyName("Controller", controllerName)
        Class controllerClass = controller?.clazz
        def method = controllerClass?.getMethod(actionName ?: "index", [] as Class[])

        if ((controllerClass?.isAnnotationPresent(RequireApiKey) && !method?.isAnnotationPresent(SkipApiKeyCheck))
                || method?.isAnnotationPresent(RequireApiKey)) {

            boolean ok = false
            boolean legacyKeyOk = false
            boolean jwtOk = false

            String clientIp = getClientIP(request)

            if (whitelistEnabled) {
                List<String> whiteList = buildWhiteList()
                ok = checkClientIp(clientIp, whiteList)
                if (ok){
                    return true
                }
            }

            if (!ok && legacyApiKeysEnabled){
                String apiKey = request.getHeader(headerName)
                if (apiKey) {
                    legacyKeyOk = legacyApiKeyService.checkApiKey(apiKey).valid
                    if (legacyKeyOk) {
                        return true
                    }
                }
            }

            if (!ok && jwtApiKeysEnabled){
                String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER_NAME)
                AuthenticatedUser authenticatedUser = jwtCheckService.checkJWT(authorizationHeader)
                request.setProperty("authenticatedUser", authenticatedUser)
                if (authenticatedUser){
                    return true
                }
            }

            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden")
            false
        } else {
            true
        }
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
        String config = grailsApplication.config.navigate('security', 'apikey', 'ip', 'whitelist')
        if (config) {
            whiteList.addAll(config.split(',').collect({ String s -> s.trim() }))
        }
        log.debug('{}', whiteList)
        whiteList
    }

    def getClientIP(HttpServletRequest request) {
        // External requests may be proxied by Apache, which uses X-Forwarded-For to identify the original IP.
        String ip = request.getHeader("X-Forwarded-For")
        if (!ip || LOOPBACK_ADDRESSES.contains(ip)) {
            // don't accept localhost from the X-Forwarded-For header, since it can be easily spoofed.
            ip = request.getRemoteHost()
        }
        ip
    }
}