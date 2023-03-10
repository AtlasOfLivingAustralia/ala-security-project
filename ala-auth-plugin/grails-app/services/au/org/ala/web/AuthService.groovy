package au.org.ala.web

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.userdetails.UserDetailsFromIdListRequest
import au.org.ala.userdetails.UserDetailsFromIdListResponse
import grails.plugin.cache.Cacheable
import grails.web.mapping.LinkGenerator
import org.springframework.beans.factory.annotation.Autowired

import javax.servlet.http.HttpServletRequest

class AuthService implements IAuthService {

    static transactional = false

    def grailsApplication
    def userListService
    UserDetailsClient userDetailsClient
    // Delegate the auth service implementation to one for our auth config

    IAuthService delegateService

    @Autowired
    LinkGenerator linkGenerator

    String getEmail() {
        delegateService.getEmail()
    }

    String getUserName() {
        delegateService.getUserName()
    }

    String getUserId() {
        delegateService.getUserId()
    }

    String getDisplayName() {
        delegateService.getDisplayName()
    }

    String getFirstName() {
        delegateService.getFirstName()
    }

    String getLastName() {
        delegateService.getLastName()
    }

    boolean userInRole(String role) {
        delegateService.userInRole(role)
    }

    UserDetails userDetails() {
        delegateService.userDetails()
    }

    String loginUrl(String path) {
        delegateService.loginUrl(path)
    }

    String loginUrl(HttpServletRequest request) {

        def requestPath = request.forwardURI ? ((request.forwardURI.startsWith('/') ? '' : '/') + request.forwardURI) : ''
        def requestQuery = request.queryString ? (request.queryString.startsWith('?') ? '' : '?') + request.queryString : ''

        loginUrl("${requestPath}${requestQuery}")
    }

    UserDetails getUserForUserId(String userId, boolean includeProps = true) {
        return getUserForUserIdInternal(userId, includeProps).orElse(null)
    }

    @Cacheable("userDetailsCache")
    Optional<UserDetails> getUserForUserIdInternal(String userId, boolean includeProps = true) {
        if (!userId) return Optional.empty() // this would have failed anyway
        def call = userDetailsClient.getUserDetails(userId, includeProps)
        try {
            def response = call.execute()

            if (response.successful) {
                return Optional.of(response.body())
            } else {
                log.warn("Failed to retrieve user details for userId: $userId, includeProps: $includeProps. Error was: ${response.message()}")
            }
        } catch (Exception ex) {
            log.error("Exception caught trying get find user details for $userId.", ex)
        }
        return Optional.empty()
    }

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
    def getUserDetailsById(List<String> userIds, boolean includeProps = true) {
        return getUserDetailsByIdInternal(userIds, includeProps).orElse(null)
    }

    @Cacheable("userDetailsByIdCache")
    Optional<UserDetailsFromIdListResponse> getUserDetailsByIdInternal(List<String> userIds, boolean includeProps = true) {
        def call = userDetailsClient.getUserDetailsFromIdList(new UserDetailsFromIdListRequest(userIds, includeProps))
        try {
            def response = call.execute()
            if (response.successful) {
                return Optional.of(response.body())
            } else {
                log.warn("Failed to retrieve user details. Error was: ${response.message()}")
            }
        } catch (Exception e) {
            log.error("Exception caught retrieving userdetails for ${userIds}", e)
        }
        return Optional.empty()
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
