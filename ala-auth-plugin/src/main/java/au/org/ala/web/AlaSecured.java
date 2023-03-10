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
     *
     * @return the list of roles
     */
    String[] value() default {};

    /**
     * Change the behaviour such that the user may be anonymous
     * @return whether the user may be anonymous
     */
    boolean anonymous() default false;

    /**
     * Change the behaviour such that the user must have only one role from the roles list to have access to the method
     * @return whether any role from the list is acceptable
     */
    boolean anyRole() default false;

    /**
     * Change the behaviour such that the user must *not* have any roles from the roles list to have access to the method
     * @return whether having any role from the list is unacceptable
     */
    boolean notRoles() default false;

    /**
     * Name of the controller to redirect to, defaults to current controller
     * @return The Grails controller to redirect to if authorization fails
     */
    String controller() default "";
    String redirectController() default "";

    /**
     * Name of the action to redirect to, defaults to index
     * @return The action to redirect to if authorization fails
     */
    String action() default "";//"index";
    String redirectAction() default "";//"index";

    String view() default "";

    /**
     * The context relative uri to redirect to, this takes precedent over the controller if specified.
     * @return the URI to redirect to if authorization fails
     */
    String redirectUri() default "";

    /**
     * Status code to return instead of redirecting, takes precendence over Uri if specified
     * @return The status code to return
     */
    int statusCode() default 0;

    /**
     * The message to put in flashScope.errorMessage, set to null to disable.
     * @return The flash scope message to use if authorization fails
     */
    String message() default "Permission denied";

    /**
     * Use a servlet forward instead of a redirect
     * @return true to use forward instead of redirect
     */
    boolean forward() default false;
}
