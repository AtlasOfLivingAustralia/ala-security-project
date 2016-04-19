package au.org.ala.ws.ast

import au.org.ala.ws.validation.ValidatedParameter
import grails.web.RequestParameter
import groovy.transform.CompileStatic
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.ClassHelper
import org.codehaus.groovy.ast.expr.ClassExpression
import org.codehaus.groovy.ast.expr.ConstantExpression
import org.codehaus.groovy.control.CompilePhase
import org.codehaus.groovy.control.SourceUnit
import org.codehaus.groovy.transform.ASTTransformation
import org.codehaus.groovy.transform.GroovyASTTransformation
import org.codehaus.groovy.ast.MethodNode
import org.codehaus.groovy.ast.AnnotationNode
import org.codehaus.groovy.ast.Parameter

import javax.validation.Constraint

@CompileStatic
@GroovyASTTransformation(phase = CompilePhase.SEMANTIC_ANALYSIS)
class BeanValidationAST implements ASTTransformation {
    @Override
    void visit(ASTNode[] nodes, SourceUnit source) {
        source?.AST?.classes?.each { clazz ->
            if (clazz.nameWithoutPackage.endsWith("Controller")) {
                // Do not remove this print statement: it helps (A LOT) when trying to determine if the transformation
                // was actually applied to a class!! This only executes at compile time.
                println "Applying Bean Validation AST Transformation to ${clazz.name}"
                List methods = clazz.methods

                methods.each { MethodNode method ->
                    method.getParameters()?.each { Parameter parameter ->
                        AnnotationNode validator = null

                        if (!parameter.getAnnotations(ClassHelper.make(ValidatedParameter))) {
                            parameter.getAnnotations()?.each { AnnotationNode annotation ->
                                if (annotation.classNode.getAnnotations(ClassHelper.make(Constraint))) {
                                    String paramName = getParamName(parameter)

                                    if (!annotation.getMember("message")) {
                                        annotation.setMember("message", new ConstantExpression("${paramName} {${annotation.classNode.name}.message}".toString()))
                                    }

                                    AnnotationNode validatorAnnotation = new AnnotationNode(ClassHelper.make(ValidatedParameter))
                                    validatorAnnotation.addMember("paramName", new ConstantExpression(paramName))
                                    validatorAnnotation.addMember("paramType", new ClassExpression(parameter.type))
                                    validator = validatorAnnotation
                                }
                            }

                            if (validator) {
                                parameter.addAnnotation(validator)
                            }
                        }
                    }
                }
            }
        }
    }

    // grails allows method parameter names to be explicitly mapped to request parameters where the names do not match
    private String getParamName(Parameter parameter) {
        String paramName = parameter.name

        List<AnnotationNode> requestParamAnnotations = parameter.getAnnotations(ClassHelper.make(RequestParameter))
        if (requestParamAnnotations) {
            paramName = ((ConstantExpression)requestParamAnnotations[0].getMember("value"))?.value
        }

        paramName
    }
}