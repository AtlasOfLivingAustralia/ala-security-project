package au.org.ala.web

import grails.core.GrailsApplication
import groovy.transform.CompileStatic

import javax.annotation.PostConstruct

@CompileStatic
class AlaSecuredInterceptor {

    // Run before other interceptors since we might fail the request
    int order = HIGHEST_PRECEDENCE + 50

    SecurityPrimitives securityPrimitives
    GrailsApplication grailsApplication

    AlaSecuredInterceptor() {
//        matchAll().except(uri: '/error')
    }

    @PostConstruct
    void init() {
        AnnotationMatcher.matchAnnotation(this, grailsApplication, AlaSecured)
    }

    boolean before() {
        def annotations = AnnotationMatcher.getAnnotation(grailsApplication, controllerNamespace, controllerName, actionName, AlaSecured)
        def effectiveAnnotation = annotations.effectiveAnnotation()

        if (effectiveAnnotation) {

            boolean error = false

            if (effectiveAnnotation.anyRole() && effectiveAnnotation.notRoles()) {
                throw new IllegalArgumentException("Only one of anyRole and notRoles should be specified")
            }

            def roles = effectiveAnnotation.value()?.toList()

            if (effectiveAnnotation.anonymous() && securityPrimitives.isNotLoggedIn(request)) {
                error = false
            } else if ((roles == null || roles.empty) && securityPrimitives.isNotLoggedIn(request)) {
                error = true
            } else if (effectiveAnnotation.anyRole() && !securityPrimitives.isAnyGranted(request, roles)) {
                error = true
            } else if (effectiveAnnotation.notRoles() && !securityPrimitives.isNotGranted(request, roles)) {
                error = true
            } else if (!effectiveAnnotation.anyRole() && !securityPrimitives.isAllGranted(request, roles)) {
                error = true
            }

            if (error) {
                if (effectiveAnnotation.message()) {
                    flash.errorMessage = effectiveAnnotation.message()
                }

                def status = effectiveAnnotation.statusCode()
                if (status == 0)  status = 403

                if (params.returnTo) {
                    redirect(url: params.returnTo)
                } else if (effectiveAnnotation.redirectUri()) {
                    redirect(uri: effectiveAnnotation.redirectUri())
                } else if (!getController(effectiveAnnotation) && !getAction(effectiveAnnotation)) {
                    if (effectiveAnnotation.view()) {
                        render(status: status, view: effectiveAnnotation.view())
                    } else if (effectiveAnnotation.message()) {
                        render(status: status, text: effectiveAnnotation.message())
                    } else {
                        render(status: status)
                    }
                } else {
                    def toController = getController(effectiveAnnotation) ?: controllerName
                    def toAction = getAction(effectiveAnnotation) ?: 'index'

                    if (controllerName == toController && !annotations.actionAnnotation && !effectiveAnnotation.forward()) {
                        log.warn('Redirecting to the current controller with a Controller level @AlaSecured, this is likely to result in a redirect loop!')
                    }
                    if (effectiveAnnotation.forward()) {
                        forward(status: status, controller: toController, action: toAction)
                    } else {
                        redirect(controller: toController, action: toAction)
                    }
                }
                return false
            }
        }
        return true
    }

    boolean after() { true }

    void afterView() {
        // no-op
    }

    def getController(AlaSecured a) {
        return a.controller() ?: a.redirectController()
    }

    def getAction(AlaSecured a) {
        return a.redirectAction() ?: a.action()
    }

}