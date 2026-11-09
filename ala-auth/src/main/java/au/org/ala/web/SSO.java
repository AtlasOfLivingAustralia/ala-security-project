package au.org.ala.web;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface SSO {

    /**
     * Only authenticate the user if they're already signed in.  Non-authenticated users will
     * be returned to the app with no current principal.
     * @return whether to use "gateway" authentication for this request
     */
    boolean gateway() default false;

    /**
     * Only redirect for SSO if the user has a cookie set
     * @return whether to only SSO if the ALA-Auth cookie is present
     */
    boolean cookie() default false;

    /**
     * Name of a Grails configuration property acting as a feature flag that disables this annotation.  If the
     * property resolves to {@code true} the annotation is ignored for the request.  If the property is missing or
     * false the annotation is enforced as normal.
     * @return the configuration property name, or empty to always enforce the annotation
     */
    String disabledByFeatureFlag() default "";
}
