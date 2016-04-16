package au.org.ala.ws.ast

import au.org.ala.ws.validation.ValidatedParameter
import org.codehaus.groovy.control.CompilePhase
import spock.lang.Specification
import org.codehaus.groovy.tools.ast.TransformTestHelper

import javax.validation.constraints.NotNull
import javax.validation.constraints.Null
import javax.validation.constraints.Size

class BeanValidationASTSpec extends Specification {
    static CompilePhase PHASE = CompilePhase.SEMANTIC_ANALYSIS
    
    def "transform should add @ValidatedParameter to JSR303-annotated params for controller action methods"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
            import javax.validation.constraints.NotNull
            import javax.validation.constraints.Null
            class TestController {
              def action1(@NotNull String param1, @Null String param2, String param3) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then:
        clazz.class.getMethod("action1", String, String, String).getParameterAnnotations()[0].length == 2
        clazz.class.getMethod("action1", String, String, String).getParameterAnnotations()[0][0].annotationType() == NotNull
        clazz.class.getMethod("action1", String, String, String).getParameterAnnotations()[0][1].annotationType() == ValidatedParameter
        clazz.class.getMethod("action1", String, String, String).getParameterAnnotations()[1].length == 2
        clazz.class.getMethod("action1", String, String, String).getParameterAnnotations()[1][0].annotationType() == Null
        clazz.class.getMethod("action1", String, String, String).getParameterAnnotations()[1][1].annotationType() == ValidatedParameter
        clazz.class.getMethod("action1", String, String, String).getParameterAnnotations()[2].length == 0
    }

    def "transform should store the parameter name from the source code in the @ValidatedParameter annotation"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
            import javax.validation.constraints.NotNull
            class TestController {
              def action1(@NotNull String param1) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then:
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][1].paramName() == "param1"
    }

    def "transform should set the constraint message to the param name followed by the default message expression if message is not set"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
            import javax.validation.constraints.NotNull
            class TestController {
              def action1(@NotNull String param1) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then:
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][0].message() == "param1 {${NotNull.class.name}.message}"
    }

    def "transform should not change the constraint message if it has been set on the annotation"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
            import javax.validation.constraints.NotNull
            class TestController {
              def action1(@NotNull(message = 'test message') String param1) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then:
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][0].message() == "test message"
    }

    def "transform should store the parameter name from the @RequestParameter annotation in the @ValidatedParameter annotation"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
            import javax.validation.constraints.NotNull
            import grails.web.RequestParameter
            class TestController {
              def action1(@NotNull @RequestParameter(value="otherName") String param1) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then: "there will only be 2 annotations since RequestParameter has a retention policy of Source"
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][1].paramName() == "otherName"
    }

    def "transform should ignore classes whose names do not end in Controller"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
              import javax.validation.constraints.NotNull
              class TestClass {
              def action1(@NotNull String param1) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then:
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0].length == 1
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][0].annotationType() == NotNull
    }

    def "transform should not add or override the @ValidatedParameter annotation if it already exists"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
            import au.org.ala.ws.validation.ValidatedParameter
            import javax.validation.constraints.NotNull
            class TestController {
              def action1(@NotNull @ValidatedParameter(paramName = "test") String param1) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then:
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0].length == 2
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][0].annotationType() == NotNull
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][1].annotationType() == ValidatedParameter
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][1].paramName() == "test"
    }

    def "transform should only add the @ValidatedParameter annotation once even if a param has multiple constraints"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
            import au.org.ala.ws.validation.ValidatedParameter
            import javax.validation.constraints.NotNull
            import javax.validation.constraints.Size
            class TestController {
              def action1(@NotNull @Size(min = 2) String param1) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then:
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0].length == 3
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][0].annotationType() == NotNull
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][1].annotationType() == Size
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0][2].annotationType() == ValidatedParameter
    }

    def "transform should ignore method parameters not annotated with JSR303 annotations"() {
        setup:
        BeanValidationAST transformer = new BeanValidationAST()
        Class testClass = new TransformTestHelper(transformer, PHASE).parse '''
            class TestController {
              def action1(String param1) {
              }
            }
        '''

        when:
        def clazz = testClass.newInstance()

        then:
        clazz.class.getMethod("action1", String).getParameterAnnotations()[0].length == 0
    }
}
