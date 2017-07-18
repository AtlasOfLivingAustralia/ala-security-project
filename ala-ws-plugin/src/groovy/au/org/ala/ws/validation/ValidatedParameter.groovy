package au.org.ala.ws.validation

import au.org.ala.ws.ast.BeanValidationAST
import org.codehaus.groovy.transform.GroovyASTTransformationClass

import java.lang.annotation.ElementType
import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy
import java.lang.annotation.Target

@Retention(RetentionPolicy.RUNTIME)
@Target([ElementType.PARAMETER])
@GroovyASTTransformationClass(classes = BeanValidationAST)
public @interface ValidatedParameter {
    String paramName()

    Class paramType()
}