package au.org.ala.web

import groovy.transform.CompileStatic

import java.lang.reflect.Method
import java.lang.reflect.Modifier

@CompileStatic
class AlaSecuredInterceptor {

    // Run before other interceptors since we might fail the request
    int order = HIGHEST_PRECEDENCE + 50

    SecurityPrimitives securityPrimitives

    AlaSecuredInterceptor() {
        matchAll().except(uri: '/error')
    }

    boolean before() {
        def controller = grailsApplication.getArtefactByLogicalPropertyName("Controller", controllerName)
        Class cClazz = controller?.clazz

        if (!cClazz) {
            return true
        }

        String methodName = actionName ?: "index"
        // The action annotation may be applied to either a method or a property
        AlaSecured actionAnnotation = null
        // Look for a method on the controller whose name matches the action...
        Method method = cClazz.getMethods().find { method -> method.name == methodName && Modifier.isPublic(method.getModifiers()) }

        if (method) {
            actionAnnotation = method.getAnnotation(AlaSecured)
        } else {
            // if a method could not be found, look for a property (private field) on the class, for when actions are declared in this style:
            // def action = { ... }
            def field = cClazz.declaredFields.find { it.name == methodName }
            // If a field could not be found, it may be a spring web flow action, so look for that (name suffixed with "Flow")...
            if (!field) {
                String target = "${methodName}Flow"
                field = cClazz.declaredFields.find { it.name == target }
            }

            if (field) {
                actionAnnotation = field.getAnnotation(AlaSecured)
            }
        }

        // Action annotations trump class annotations
        AlaSecured classAnnotation = cClazz.getAnnotation(AlaSecured)
        AlaSecured effectiveAnnotation = actionAnnotation ?: classAnnotation

        if (effectiveAnnotation) {

            boolean error = false

            if (effectiveAnnotation.anyRole() && effectiveAnnotation.notRoles()) {
                throw new IllegalArgumentException("Only one of anyRole and notRoles should be specified")
            }

            def roles = effectiveAnnotation.value()?.toList()

            if ((roles == null || roles.empty) && securityPrimitives.isNotLoggedIn(request)) {
                error = true
            } else if (effectiveAnnotation.anyRole() && !securityPrimitives.isAnyGranted(roles)) {
                error = true
            } else if (effectiveAnnotation.notRoles() && !securityPrimitives.isNotGranted(roles)) {
                error = true
            } else if (!effectiveAnnotation.anyRole() && !securityPrimitives.isAllGranted(roles)) {
                error = true
            }

            if (error) {
                if (effectiveAnnotation.message()) {
                    flash.errorMessage = effectiveAnnotation.message()
                }

                if (params.returnTo) {
                    redirect(url: params.returnTo)
                } else if (effectiveAnnotation.statusCode() != 0) {
                    render(status: effectiveAnnotation.statusCode())
                } else if (effectiveAnnotation.redirectUri()) {
                    redirect(uri: effectiveAnnotation.redirectUri())
                } else {
                    def redirectController =  effectiveAnnotation.redirectController() ?: controllerName

                    if (controllerName == redirectController && !actionAnnotation) {
                        log.warn('Redirecting to the current controller with a Controller level @AlaSecured, this is likely to result in a redirect loop!')
                    }
                    redirect(controller: redirectController, action: effectiveAnnotation.redirectAction())
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

}