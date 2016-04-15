package au.org.ala.ws.filter

import javax.validation.ConstraintViolation
import javax.validation.ConstraintViolationException
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

                List<Annotation> validators = method.getParameterAnnotations()*.find { it instanceof ValidatedParameter }.flatten()

                if (validators) {
                    List parameterValues = []
                    validators.each {
                        if (it) {
                            parameterValues << params[it.paramName()]
                        }
                    }

                    def dummyControllerImpl = dummyControllers[controllerClass]
                    if (!dummyControllerImpl) {
                        dummyControllerImpl = controllerClass.newInstance()
                        dummyControllers.put(controllerClass, dummyControllerImpl)
                    }

                    Set<ConstraintViolation> violations = validator.validateParameters(dummyControllerImpl, method, parameterValues as Object[])
                    if (violations) {
                        throw new ConstraintViolationException(violations)
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
