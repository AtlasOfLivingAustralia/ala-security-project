package au.org.ala.web

import au.org.ala.cas.util.AuthenticationUtils
import com.google.gson.Gson
import grails.converters.JSON
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
        return bypass.toString().toBoolean() || inRole
    }

    Map userDetails() {
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
    UserDetails getUserForUserId(String userId, boolean includeProps = false) {
        def results = httpWebService.doPost(grailsApplication.config.userDetails.url + grailsApplication.config.userDetailsById.path + "?userName=${URLEncoder.encode(userId, 'UTF-8')}&includeProps=${includeProps}", "", "", "")
        try {

            if (!results.error) {
                def ud = results.resp
                if (ud?.userName && ud?.userId) {
                    return createUserDetailsFromJson(ud)
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
    UserDetails getUserForEmailAddress(String emailAddress, boolean includeProps = false) {
        // The user details service lookup service should accept either a numerical id or email address and respond appropriately
        return getUserForUserId(emailAddress, includeProps)
    }

    def createUserDetailsFromJson(json) {
        def ud = new UserDetails(
                userId: json.userId?.toString(),
                userName: json.userName?.toString()?.toLowerCase(),
                displayName: "${json.firstName ?: ""} ${json.lastName ?: ""}".trim()
        )

        if (json.props) {
            ud.primaryUserType = json.props.primaryUserType
            ud.secondaryUserType = json.props.secondaryUserType
            ud.organisation = json.props.organisation
            ud.city = json.props.city
            ud.state = json.props.state
            ud.telephone = json.props.telephone
        }

        if (json.roles) {
            ud.roles = new HashSet(json.roles)
        }

        return ud
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
    @Cacheable("userDetailsCache")
    def getUserDetailsById(List<String> userIds, boolean includeProps = false) {
        //def json = ([userIds: userIds, includeProps: includeProps] as JSON).toString()
        def json = Gson.newInstance().toJson([userIds: userIds, includeProps: includeProps])  // above doesn't work in unit tests :(
        def results = httpWebService.doPost(grailsApplication.config.userDetails.url + grailsApplication.config.userDetailsById.bulkPath, '', '', json, 'application/json')
        try {
            if (!results.error) {
                def resp = results.resp
                return [users: resp.users.collectEntries { [(it.key) :createUserDetailsFromJson(it.value)] }, invalidIds: resp.invalidIds.collect { it }, success: resp.success ]
            } else {
                log.warn("Failed to retrieve bulk user details.  Error message was: ${results.error}")
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