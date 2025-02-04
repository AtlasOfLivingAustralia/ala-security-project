package au.ala.org.ws.security

import java.lang.annotation.Documented
import java.lang.annotation.ElementType
import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy
import java.lang.annotation.Target

/**
 * Annotation to check that a valid api key has been provided.
 */
@Target([ElementType.TYPE, ElementType.METHOD])
@Retention(RetentionPolicy.RUNTIME)
@Documented
@interface RequireApiKey  {

    String projectIdParam() default "id"

    String redirectController() default "project"

    String redirectAction() default "index"

    /**
     * Only taken into account for JWT authentications
     * @return
     */
    String[] roles() default []

    /**
     * Only taken into account for JWT authentications.  Combined with security.jwt.scopes
     * @return
     */
    String[] scopes() default []

    /**
     * Provide a Grails configuration property name to get the scopes from.  Combined with security.jwt.scopes and scopes parameter
     * @return
     */
    String[] scopesFromProperty() default []

    boolean useCustomFilter() default false
}