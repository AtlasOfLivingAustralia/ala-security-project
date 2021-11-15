package au.ala.org.ws.security

import java.lang.annotation.Documented
import java.lang.annotation.ElementType
import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy
import java.lang.annotation.Target

/**
 * Annotation to check that a user is logged in, and optionally
 * check a list of required roles.
 */
@Target([ElementType.TYPE, ElementType.METHOD])
@Retention(RetentionPolicy.RUNTIME)
@Documented
@interface RequireAuth {
    /**
     * List of roles or configuration properties that point to roles.
     * e.g. "ROLE_ADMIN,ROLE_USER"
     * @return
     */
    String[] requiredRoles() default [];
}