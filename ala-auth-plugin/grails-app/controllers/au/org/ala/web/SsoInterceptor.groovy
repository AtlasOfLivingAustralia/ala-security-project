package au.org.ala.web

import au.org.ala.grails.AnnotationMatcher
import au.org.ala.web.config.AuthPluginConfig
import grails.core.GrailsApplication
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value

import javax.annotation.PostConstruct
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest

@CompileStatic
@Slf4j
class SsoInterceptor {

    int order = HIGHEST_PRECEDENCE

    @Value('${security.cas.enabled:true}')
    boolean enabled

    @Value('${security.oidc.enabled:false}')
    boolean oidcEnabled

    @Value('${security.cas.authCookieName:ALA-Auth}')
    String authCookieName

    @Autowired
    UserAgentFilterService userAgentFilterService

    @Autowired
    GrailsApplication grailsApplication

    @Autowired
    SSOStrategy ssoStrategy

    SsoInterceptor() {
//        matchAll().except(uri: '/error')
    }

    @PostConstruct
    void init() {
        if (enabled || oidcEnabled) {
            AnnotationMatcher.matchAnnotation(this, grailsApplication, SSO)
        }
    }

    boolean before() {
        if (!(enabled || oidcEnabled)) return true
        if (request.getAttribute(AuthPluginConfig.AUTH_FILTER_KEY)) return true

        final result = AnnotationMatcher.getAnnotation(grailsApplication, controllerNamespace, controllerName, actionName, SSO, NoSSO)
        final effectiveAnnotation = result.effectiveAnnotation()
        final actionNoSso = result.overrideAnnotation

        if (actionNoSso) return true

        if (!effectiveAnnotation) return true

        if (effectiveAnnotation.cookie() && !cookieExists(request)) {
            log.debug("{}.{}.{} requested the presence of a {} cookie but none was found", controllerNamespace, controllerName, actionName, authCookieName)
            return true
        }

        def userAgent = request.getHeader('User-Agent')
        if ((effectiveAnnotation.gateway()) && userAgentFilterService.isFiltered(userAgent)) {
            log.debug("{}.{}.{} skipping SSO because it is gateway and the user agent is filtered", controllerNamespace, controllerName, actionName)
            return true
        }

        return ssoStrategy.authenticate(request, response, effectiveAnnotation.gateway())
    }

    boolean after() { true }

    void afterView() {
        // no-op
    }

    protected boolean cookieExists(final HttpServletRequest request) {
        return request.cookies.any { Cookie cookie -> cookie.name == this.authCookieName && cookie.value}
    }

}
