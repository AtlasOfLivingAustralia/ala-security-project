package au.org.ala.web

import au.org.ala.cas.util.AuthenticationUtils
import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.userdetails.UserDetailsFromIdListRequest
import grails.plugin.cache.Cacheable
import org.springframework.web.context.request.RequestContextHolder

import javax.servlet.http.HttpServletRequest

class AuthService {

    static transactional = false

    def grailsApplication
    def userListService
    UserDetailsClient userDetailsClient

    def getEmail() {
        return AuthenticationUtils.getEmailAddress(RequestContextHolder.currentRequestAttributes().getRequest())
    }

    def getUserId() {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        def userId = AuthenticationUtils.getUserId(request)
        if (!userId) {
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

    def getDisplayName() {
        return AuthenticationUtils.getDisplayName(RequestContextHolder.currentRequestAttributes().getRequest())
    }

    def getFirstName() {
        return AuthenticationUtils.getFirstName(RequestContextHolder.currentRequestAttributes().getRequest())
    }

    def getLastName() {
        return AuthenticationUtils.getLastName(RequestContextHolder.currentRequestAttributes().getRequest())
    }

    boolean userInRole(role) {

        def inRole = AuthenticationUtils.isUserInRole(RequestContextHolder.currentRequestAttributes().getRequest(), role)
        def bypass = grailsApplication.config.security.cas.bypass
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

    @Cacheable("userDetailsCache")
    UserDetails getUserForUserId(String userId, boolean includeProps = true) {
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

    @Cacheable("userDetailsCache")
    UserDetails getUserForEmailAddress(String emailAddress, boolean includeProps = true) {
        // The user details service lookup service should accept either a numerical id or email address and respond appropriately
        return getUserForUserId(emailAddress, includeProps)
    }

    /**
     *
     * Do a bulk lookup of user ids from the userdetails service.  Accepts a list of numeric user ids and returns a
     * map that looks like this:
     *
     * <pre>
[
  users:[
     "546": UserDetails(userId: "546", userName: "user1@gmail.com", displayName: "First User"),
     "4568": UserDetails(userId: "4568", userName: "user2@hotmail.com", displayName: "Second User"),
     "8744": UserDetails(userId: "8744", userName: "user3@fake.edu.au", displayName: "Third User")
  ],
  invalidIds:[ 575 ],
  success: true
]
     </pre>
     *
     * @param userIds
     * @return
     */
    @Cacheable("userDetailsByIdCache")
    def getUserDetailsById(List<String> userIds, boolean includeProps = true) {
        def call = userDetailsClient.getUserDetailsFromIdList(new UserDetailsFromIdListRequest(userIds, includeProps))
        try {
            def response = call.execute()
            if (response.successful) {
                return response.body()
            } else {
                log.warn("Failed to retrieve user details. Error was: ${response.message()}")
            }
        } catch (Exception e) {
            log.error("Exception caught retrieving userdetails for ${userIds}", e)
        }
        return null
    }

    /**
     * @deprecated - use a lookup service e.g. getUserForEmailAddress()
     * @return
     */
    Map<String, UserDetails> getAllUserNameMap() {
        def userListMap = [:]

        try {
            def userListJson = userListService.getFullUserList()
            userListJson.eachWithIndex { user, i ->
                userListMap.put(user.userName?.toLowerCase(), user) // username as key (email address)
            }
        } catch (Exception e) {
            log.error "Cache refresh error: " + e.message, e
        }

        return userListMap
    }


    /**
     * @deprecated - use a lookup service e.g. getUserForEmailAddress()
     * @return
     */
    def getAllUserNameList() {
        def userList = []
        try {
            def userListJson = userListService.getFullUserList()
            userListJson.eachWithIndex { user, i ->
                userList.add(user)
            }
        } catch (Exception e) {
            log.error "Cache refresh error: " + e.message, e
        }

        return userList
    }

}
