package au.ala.org.ws.security

import java.lang.annotation.Documented
import java.lang.annotation.ElementType
import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy
import java.lang.annotation.Target

/**
 * Annotation to skip the check for a valid api key. This annotation can be used to exclude specific actions when
 * {@link RequireAuth} has been specified at the class level because the majority of actions require the key.
 */
@Target([ElementType.TYPE, ElementType.METHOD])
@Retention(RetentionPolicy.RUNTIME)
@Documented
@interface SkipAuthCheck {
}