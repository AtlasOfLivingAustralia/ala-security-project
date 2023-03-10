package au.org.ala.web

/**
 * Generalise the Auth Service implementation that depends on the kind of authentication being used.
 */
interface IAuthService {

    /**
     * Get the current user's email address
     * @return the current user's email address
     */
    String getEmail()

    /**
     * Get the current user's preferred username
     * @return the current user's preferred username
     */
    String getUserName()

    /**
     * Get the current user's id
     * @return the current user's id
     */
    String getUserId()

    /**
     * Get the current user's display name
     * @return the current user's display name
     */
    String getDisplayName()

    /**
     * Get the current user's first name
     * @return the current user's first name
     */
    String getFirstName()

    /**
     * Get the current user's last name
     * @return the current user's last name
     */
    String getLastName()

    /**
     * Is the current user in the given role
     * @return true if the current user has the given role
     */
    boolean userInRole(String role)

    /**
     * UserDetails for the current user
     * @return UserDetails for the current user
     */
    UserDetails userDetails()


    /**
     * Get the login URL for the current auth service
     * @param returnUrl The url to return to.
     * @return The login url
     */
    String loginUrl(String returnUrl)
}
