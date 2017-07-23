package au.org.ala.ws.security

import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.org.ala.ws.security.service.ApiKeyService
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j

import javax.servlet.http.HttpServletRequest

@CompileStatic
@Slf4j
class ApiKeyInterceptor {
    ApiKeyService apiKeyService

    static final int STATUS_UNAUTHORISED = 403
    static final String API_KEY_HEADER_NAME = "apiKey"
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
            List<String> whiteList = buildWhiteList()
            String clientIp = getClientIP(request)
            boolean ipOk = checkClientIp(clientIp, whiteList)
            if (!ipOk) {
                boolean keyOk = apiKeyService.checkApiKey(request.getHeader(headerName)).valid
                log.debug "IP ${clientIp} ${ipOk ? 'is' : 'is not'} ok. Key ${keyOk ? 'is' : 'is not'} ok."

                if (!keyOk) {
                    log.warn(ipOk ? "No valid api key for ${controllerName}/${actionName}" :
                            "Non-authorised IP address - ${clientIp}")
                    response.status = STATUS_UNAUTHORISED
                    response.sendError(STATUS_UNAUTHORISED, "Forbidden")
                    return false
                }
            } else {
                log.debug("IP ${clientIp} is exempt from the API Key check. Authorising.")
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
