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

                // grails url mapping like "/home controller: 'home'" will result in a null actionName but maps to index
                String methodName = actionName ?: "index"

                // the following works because action methods cannot be overloaded in Grails Controllers - therefore we
                // will only ever have 1 declared method of a given name with parameters (grails will auto generate a no-arg
                // version of the method, but we're only interested in the version with params
                Method method = controllerClass?.getDeclaredMethods()?.find {
                    it.name == methodName && it.parameterTypes?.length > 0
                }

                if (method) {
                    List<Annotation> validators = method.getParameterAnnotations()*.find {
                        it instanceof ValidatedParameter
                    }?.flatten()?.findResults { it }

                    if (validators) {
                        List parameterValues = []
                        validators.each {
                            if (it) {
                                String paramString = params.containsKey(it.paramName()) ? params[it.paramName()] : null
                                parameterValues << (paramString ? paramString.asType(it.paramType()) : null)
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

                        return violations == null || violations.isEmpty()
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
