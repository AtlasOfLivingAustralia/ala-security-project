package au.org.ala.ws.ast

import au.org.ala.ws.validation.ValidatedParameter
import groovy.transform.CompileStatic
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.ClassHelper
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
        source.AST.classes.each { clazz ->
            if (clazz.nameWithoutPackage.endsWith("Controller")) {
                List methods = clazz.methods

                methods.each { MethodNode method ->
                    method.getParameters()?.each { Parameter parameter ->
                        List<AnnotationNode> validators = []

                        // TODO add support for @RequestParameter grails annotation
                        // TODO check for support for cross-field annotations and method level constraints?
                        parameter.getAnnotations()?.each { AnnotationNode annotation ->
                            if (annotation.classNode.getAnnotations(ClassHelper.make(Constraint))) {
                                AnnotationNode validatorAnnotation = new AnnotationNode(ClassHelper.make(ValidatedParameter))
                                validatorAnnotation.addMember("paramName", new ConstantExpression(parameter.getName()))
                                validators << validatorAnnotation
                            }
                        }

                        validators?.each { AnnotationNode node ->
                            parameter.addAnnotation(node)
                        }
                    }
                }
            }
        }
    }
}