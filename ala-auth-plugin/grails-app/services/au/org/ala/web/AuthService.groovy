package au.org.ala.web

import au.org.ala.cas.util.AuthenticationUtils
import net.sf.json.JSONArray
import net.sf.json.JSONObject
import org.springframework.cache.annotation.Cacheable
import org.springframework.web.context.request.RequestContextHolder

import javax.servlet.http.HttpServletRequest

class AuthService {

    static transactional = false

    def grailsApplication
    def userListService
    def httpWebService

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

    public boolean userInRole(role) {

        def inRole = AuthenticationUtils.isUserInRole(RequestContextHolder.currentRequestAttributes().getRequest(), role)
        def bypass = grailsApplication.config.security.cas.bypass
        log.debug("userInRole(${role}) - ${inRole} (bypassing CAS - ${bypass})")
        return bypass || inRole
    }

    def userDetails() {
        def attr = RequestContextHolder.currentRequestAttributes()?.getUserPrincipal()?.attributes
        def details = null

        if (attr) {
            details = [
                userId:attr?.userid?.toString(),
                email: attr?.email?.toString()?.toLowerCase(),
                userDisplayName: "${attr?.firstname?:""} ${attr?.lastname?:""}".trim()
            ]
        }

        details
    }

    @Cacheable("userDetailsCache")
    UserDetails getUserForUserId(String userId) {
        def results = httpWebService.doPost(grailsApplication.config.userDetails.url + grailsApplication.config.userDetailsById.path + "?userName=${userId}", "", "", "")
        try {

            if (!results.error) {
                def ud = results.resp
                if (ud?.userName && ud?.userId) {
                    return new UserDetails(
                        userId: ud.userId?.toString(),
                        userName: ud.userName?.toString()?.toLowerCase(),
                        displayName: "${ud.firstName ?: ""} ${ud.lastName ?: ""}".trim()
                    )
                }
            } else {
                log.warn("Failed to retrieve user details. Error message was: ${results.error}")
            }
        } catch (Exception ex) {
            log.error("Exception caught trying get find user details for ${userId}.", ex)
        }
        return null
    }

    @Cacheable("userDetailsCache")
    UserDetails getUserForEmailAddress(String emailAddress) {
        // The user details service lookup service should accept either a numerical id or email address and respond appropriately
        return getUserForUserId(emailAddress)
    }

    /**
     * @deprecated - use a lookup service e.g. getUserForEmailAddress()
     * @return
     */
    Map<String, UserDetails> getAllUserNameMap() {
        def userListMap = [:]

        try {
            def userListJson = userListService.getFullUserList()
            if (userListJson instanceof JSONObject) {
                // works with path = getUserListWithIds
                userListJson.keySet().each { id ->
                    userListMap.put(String.valueOf(id), userListJson[id]);
                }
            } else if (userListJson instanceof JSONArray) {
                // works with path = getUserListFull
                userListJson.eachWithIndex { user, i ->
                    def userDetails = new UserDetails(userId: user.id, displayName: "${user.firstName} ${user.lastName}", userName: user.userName)
                    userListMap.put(String.valueOf(user.id), userDetails);
                }
            } else if (userListJson instanceof ArrayList) {
                // works with path = getUserListFull
                userListJson.eachWithIndex { user, i ->
                    def userDetails = new UserDetails(userId: user.id, displayName: "${user.firstName} ${user.lastName}", userName: user.userName)
                    userListMap.put(user.userName?.toLowerCase(), userDetails); // username as key (email address)
                }
            } else {
                log.info "error -  ${userListJson.getClass()}" // + ": ${userListJson}"
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
            if (userListJson instanceof JSONObject) {
                // works with path = getUserListWithIds
                userListJson.keySet().each { id ->
                    userList.add(userListJson[id]);
                }
            } else if (userListJson instanceof JSONArray) {
                // works with path = getUserListFull
                userListJson.eachWithIndex { user, i ->
                    def userDetails = new UserDetails(userId: user.id, displayName: "${user.firstName} ${user.lastName}", userName: user.userName)
                    userList.add(userDetails);
                }
            } else {
                log.info "error -  " + userListJson.getClass() + ": ${userListJson}"
            }
        } catch (Exception e) {
            log.error "Cache refresh error: " + e.message, e
        }

        return userList
    }

}