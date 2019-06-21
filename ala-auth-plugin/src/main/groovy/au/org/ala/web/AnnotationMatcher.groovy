package au.org.ala.web

import grails.core.GrailsApplication
import grails.core.GrailsClass
import grails.artefact.Interceptor
import grails.core.GrailsControllerClass
import groovy.util.logging.Slf4j

import java.lang.annotation.Annotation
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier

@Slf4j
class AnnotationMatcher {

    static void matchAnnotation(Interceptor interceptor, GrailsApplication grailsApplication, Class<? extends Annotation> annotation) {
        def controllers = grailsApplication.getArtefacts('Controller')
        controllers.each { GrailsClass controller ->
            final controllerName = controller.logicalPropertyName
            def clazz = controller.clazz
            def namespace = clazz.declaredFields.find { Field field -> field.name == 'namespace' && Modifier.isPublic(field.modifiers) }?.get(null)
            def classAnnotation =  clazz.getAnnotation(annotation)
            if (classAnnotation) {
                log.debug('Matching namespace: {}, controller: {}, action: * to interceptor: {}', namespace, controllerName, interceptor.class.name)
                interceptor.match(namespace: namespace, controller: controllerName, action: '*')
            } else {
                clazz.methods
                        .findAll { Method method -> method.getAnnotation(annotation) != null && Modifier.isPublic(method.getModifiers() ) }
                        .each { Method method ->
                            final actionName = method.name
                            log.debug('Matching namespace: {}, controller: {}, action: {} to interceptor: {}', namespace, controllerName, actionName, interceptor.class.name)
                            interceptor.match(namespace: namespace, controller: controllerName, action: actionName)
                        }
                clazz.declaredFields
                        .findAll { Field field -> field.getAnnotation(annotation) != null }
                        .each { Field field ->
                            final actionName = field.name
                            log.debug('Matching namespace: {}, controller: {}, action: {} to interceptor: {}', namespace, controllerName, actionName, interceptor.class.name)
                            interceptor.match(namespace: namespace, controller: controllerName, action: actionName.endsWith('Flow') ? actionName.substring(0, actionName.length() - 4) : actionName)
                        }
            }
        }
    }

    static GrailsClass getControllerByNamespaceAndLogicalName(GrailsApplication grailsApplication, String namepsace, String controllerName) {
        def artefacts = grailsApplication.getArtefactInfo('Controller')
        return artefacts.grailsClasses.find {
            it.logicalPropertyName == controllerName && it.namespace == namepsace
        }
    }

    static <T extends Annotation, U extends Annotation> AnnotationResult<T, U> getAnnotation(GrailsApplication grailsApplication, String namespace, String controllerName, String actionName, Class<T> annotation, Class<U> overrideAnnotationType = null) {
//        def controller = grailsApplication.getArtefactByLogicalPropertyName('Controller', controllerName)
        def controller = getControllerByNamespaceAndLogicalName(grailsApplication, namespace, controllerName)
        Class cClazz = controller?.clazz

        if (!cClazz) {
            return new AnnotationResult<T, U>()
        }

        String methodName = actionName ?: "index"
        // The action annotation may be applied to either a method or a property
        Annotation actionAnnotation
        Annotation overrideAnnotation
        // Look for a method on the controller whose name matches the action...
        def action =
                cClazz.methods.find { Method method -> method.name == methodName && Modifier.isPublic(method.modifiers) } ?: findField(cClazz, methodName)

        if (action) {
            actionAnnotation = action.getAnnotation(annotation)
            if (overrideAnnotationType) {
                overrideAnnotation = action.getAnnotation(overrideAnnotationType)
            } else {
                overrideAnnotation = null
            }
        } else {
            actionAnnotation = null
            overrideAnnotation = null
        }

        Annotation classAnnotation = cClazz.getAnnotation(annotation)
        return new AnnotationResult<T, U>(controllerAnnotation: classAnnotation, actionAnnotation: actionAnnotation, overrideAnnotation: overrideAnnotation)
    }

    static Field findField(Class clazz, String actionName) {
        // if a method could not be found, look for a property (private field) on the class, for when actions are declared in this style:
        // def action = { ... }
        final String flowActionName = "${actionName}Flow"

        return clazz.declaredFields.find { it.name == actionName } ?: clazz.declaredFields.find { it.name == flowActionName }
    }

    static class AnnotationResult<T extends Annotation, U extends Annotation> {
        T controllerAnnotation
        T actionAnnotation
        U overrideAnnotation

        T effectiveAnnotation() {
            actionAnnotation ?: controllerAnnotation
        }
    }
}
