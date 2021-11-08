package au.org.ala.ws.security

import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j

import javax.servlet.http.HttpServletResponse
import java.security.Principal

/**
 * An authentication interceptor that checks a user is logged in and has certain permissions.
 *
 *
 */
@CompileStatic
@Slf4j
class AlaAuthInterceptor {

    AlaAuthInterceptor() {
        matchAll()
    }

    /**
     * Executed before a matched action.
     *
     * @return Whether the action should continue and execute
     */
    boolean before() {

        def controller = grailsApplication.getArtefactByLogicalPropertyName("Controller", controllerName)
        Class controllerClass = controller?.clazz
        def method = controllerClass?.getMethod(actionName ?: "index", [] as Class[])

        if ((controllerClass?.isAnnotationPresent(RequireApiKey) && !method?.isAnnotationPresent(SkipApiKeyCheck))
                || method?.isAnnotationPresent(RequireApiKey)) {

            Principal userPrincipal = request.getUserPrincipal()
            if (!userPrincipal){
                return false
            }

            RequireApiKey classLevelRequireApiKey = controllerClass.getAnnotation(RequireApiKey.class)
            RequireApiKey methodLevelRequireApiKey = method.getAnnotation(RequireApiKey.class)

            if (classLevelRequireApiKey && classLevelRequireApiKey.requiredRoles()){
                // resolve role property
                String[] requiredRoles = classLevelRequireApiKey.requiredRoles().split(",")
                // check roles
                List roles = [] //userPrincipal.getRoles()

                requiredRoles.each { requiredRole ->
                    //TODO check grailsApplication.config.'requiredRole'
                    if (!roles.contains(requiredRole)){
                        return false
                    }
                }
            }

            if (methodLevelRequireApiKey && methodLevelRequireApiKey.requiredRoles()){

                // resolve role property
                String[] requiredRoles = methodLevelRequireApiKey.requiredRoles().split(",")
                // check roles
                List roles = [] //userPrincipal.getRoles()
                //TODO check grailsApplication.config.'requiredRole'
                requiredRoles.each { requiredRole ->
                    if (!roles.contains(requiredRole)){
                        return false
                    }
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
}