package au.org.ala.web

import au.org.ala.cas.util.AuthenticationUtils
import au.org.ala.userdetails.UserDetailsClient
import groovy.util.logging.Slf4j
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.util.UriComponentsBuilder

import javax.servlet.http.HttpServletRequest

/**
 * CAS based implementation of the generic auth service methods.
 */
@Slf4j
class CasAuthService implements IAuthService {

    private UserDetailsClient userDetailsClient
    private boolean casBypass
    private String casLoginUrl

    CasAuthService(UserDetailsClient userDetailsClient, boolean casBypass, String casLoginUrl) {
        this.casBypass = casBypass
        this.userDetailsClient = userDetailsClient
        this.casLoginUrl = casLoginUrl
    }

    String getEmail() {
        return AuthenticationUtils.getEmailAddress(RequestContextHolder.currentRequestAttributes().getRequest())
    }

    String getUserName() {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        def username = AuthenticationUtils.getPrincipalAttribute(request, "username") // check this
        return username
    }

    String getUserId() {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        def userId = AuthenticationUtils.getUserId(request)
        if (!userId) {
            log.warn("Attempt to get email address from cookie, this is deprecated and may not be supported in the future.")
            // try the email address, and working backwards from there
            def emailAddress = AuthenticationUtils.getEmailAddress(request)
            if (emailAddress) {
                def user = getUserForEmailAddress(emailAddress)
                if (user) {
                    userId = user.userId
                }
            }
        }
        return userId
    }


    String getDisplayName() {
        return AuthenticationUtils.getDisplayName(RequestContextHolder.currentRequestAttributes().getRequest())
    }

    String getFirstName() {
        return AuthenticationUtils.getFirstName(RequestContextHolder.currentRequestAttributes().getRequest())
    }

    String getLastName() {
        return AuthenticationUtils.getLastName(RequestContextHolder.currentRequestAttributes().getRequest())
    }

    boolean userInRole(String role) {

        def inRole = AuthenticationUtils.isUserInRole(RequestContextHolder.currentRequestAttributes().getRequest(), role)
        def bypass = casBypass
        log.debug("userInRole(${role}) - ${inRole} (bypassing CAS - ${bypass})")
        return bypass.toString().toBoolean() || inRole
    }

    UserDetails userDetails() {
        def attr = RequestContextHolder.currentRequestAttributes()?.getUserPrincipal()?.attributes
        def details = null

        if (attr) {
            details = new UserDetails(
                    userId:attr?.userid?.toString(),
                    userName: attr?.email?.toString()?.toLowerCase(),
                    firstName: attr?.firstname?.toString() ?: "",
                    lastName: attr?.lastname?.toString() ?: "",
                    locked: attr?.locked?.toBoolean() ?: false,
                    organisation: attr?.organisation?.toString() ?: "",
                    city: attr?.country?.toString() ?: "",
                    state: attr?.state?.toString() ?: "",
                    country: attr?.country?.toString() ?: "",
                    roles: AuthenticationUtils.getUserRoles(RequestContextHolder.currentRequestAttributes().request)
            )
        }

        details
    }

    @Override
    String loginUrl(String returnUrl) {
        def builder = UriComponentsBuilder.fromHttpUrl(casLoginUrl)
        builder.queryParam('service', returnUrl)
        return builder.build(true).toUriString()
    }

    /**
     * XXX Simply copied here to prevent circular dependency.
     * @param email Email
     * @param includeProps Props
     * @return
     */
    private UserDetails getUserForEmailAddress(String email, boolean includeProps = true) {
        if (!userId) return null // this would have failed anyway
        def call = userDetailsClient.getUserDetails(userId, includeProps)
        try {
            def response = call.execute()

            if (response.successful) {
                return response.body()
            } else {
                log.warn("Failed to retrieve user details for userId: $userId, includeProps: $includeProps. Error was: ${response.message()}")
            }
        } catch (Exception ex) {
            log.error("Exception caught trying get find user details for $userId.", ex)
        }
        return null
    }
}
