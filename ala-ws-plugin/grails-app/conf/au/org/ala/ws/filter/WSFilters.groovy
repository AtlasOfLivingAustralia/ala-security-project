package au.org.ala.ws.filter

import org.apache.http.HttpStatus

import javax.validation.ConstraintViolation
import java.lang.reflect.Method
import java.lang.annotation.Annotation
import au.org.ala.ws.validation.ValidatedParameter
import javax.validation.Validation
import javax.validation.ValidatorFactory
import javax.validation.executable.ExecutableValidator
import java.util.concurrent.ConcurrentHashMap

class WSFilters {

    static ValidatorFactory factory = Validation.buildDefaultValidatorFactory()
    static ExecutableValidator validator = factory.getValidator().forExecutables()
    static Map dummyControllers = [:] as ConcurrentHashMap

    def filters = {
        all(controller:'*', action:'*') {
            before = {
                def controller = grailsApplication.getArtefactByLogicalPropertyName("Controller", controllerName)
                Class controllerClass = controller?.clazz
                // the following works because action methods cannot be overloaded in Grails Controllers - therefore we
                // will only ever have 1 declared method of a given name.
                Method method = controllerClass?.getDeclaredMethods()?.find { it.name == actionName }

                List<Annotation> validators = method.getParameterAnnotations()*.find { it instanceof ValidatedParameter }?.flatten()?.findResults { it }

                if (validators) {
                    List parameterValues = []
                    validators.each {
                        if (it) {
                            parameterValues << (params.containsKey(it.paramName()) ? params[it.paramName()] : null)
                        }
                    }

                    // We need to validate against a dummy instance of the concrete controller class, because the
                    // instance available to the filter is a DefaultGrailsControllerClass, which is not actually
                    // validateable (fails the hasConstraints check in the validator implementation)
                    def dummyControllerImpl = dummyControllers[controllerClass]
                    if (!dummyControllerImpl) {
                        dummyControllerImpl = controllerClass.newInstance()
                        dummyControllers.put(controllerClass, dummyControllerImpl)
                    }

                    Set<ConstraintViolation> violations = validator.validateParameters(dummyControllerImpl, method, parameterValues as Object[])
                    if (violations) {
                        log.debug("Request validation failed: ${violations}")
                        response.status = HttpStatus.SC_BAD_REQUEST
                        response.sendError(HttpStatus.SC_BAD_REQUEST, "Request validation failed: ${violations*.message.join("; ")}")
                    }
                }
            }

            after = { Map model ->

            }

            afterView = { Exception e ->
            }
        }
    }
}
