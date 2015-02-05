package au.org.ala.web;

import java.lang.annotation.*;

/**
 * Cut down version of the Spring Security @Secured annotation that will allow role based authorisation
 * on Grails controllers and controller actions *only*.
 *
 * @author Simon Bear (simon.bear@csiro.au)
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
public @interface AlaSecured {
    /**
     * A list of roles that the user must have to have access to the method, if omitted then the user must be
     * logged in.
     */
    public String[] value() default {};

    /**
     * Change the behaviour such that the user must have only one role from the roles list to have access to the method
     */
    public boolean anyRole() default false;

    /**
     * Change the behaviour such that the user must *not* have any roles from the roles list to have access to the method
     */
    public boolean notRoles() default false;

    /**
     * Name of the controller to redirect to, defaults to current controller
     */
    public String redirectController() default "";

    /**
     * Name of the action to redirect to, defaults to index
     */
    public String redirectAction() default "index";

    /**
     * The context relative uri to redirect to, this takes precedent over the controller if specified.
     */
    public String redirectUri() default "";

    /**
     * Status code to return instead of redirecting, takes precendence over Uri if specified
     */
    public int statusCode() default 0;

    /**
     * The message to put in flashScope.errorMessage, set to null to disable.
     */
    public String message() default "Permission denied";
}
