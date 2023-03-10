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
     */
    boolean gateway() default false;

    /**
     * Only redirect for SSO if the user has a cookie set
     */
    boolean cookie() default false;
}
