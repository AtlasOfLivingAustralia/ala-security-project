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
@interface RequireAuth {
    /**
     * Comma separated list of roles or configuration properties that point to roles.
     *
     * e.g. "ROLE_ADMIN,ROLE_USER"
     *
     * or "security.role.myrole" which resolves to security.role.myrole=MY_ROLE in application.yml or application.groovy
     *
     * @return
     */
    String[] requiredRoles() default [];
}