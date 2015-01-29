package au.org.ala.web

import net.sf.json.JSONArray
import net.sf.json.JSONObject
import org.springframework.cache.annotation.Cacheable

/**
 * This service has one method that returns a large list of objects containing data about ALA users.
 *
 * This method has been split from the AuthService because it is an expensive call, and is used internally by other auth service methods, and so should
 * be cached. Service methods called by other methods on the same service do not get cached (because the caching is implemented via proxy wrappers),
 * so we stick it in a different service
 */
class UserListService {

    static transactional = false

    def httpWebService, grailsApplication

    @Cacheable("userListCache")
    def getFullUserList() {
        checkConfig()
        try {
            return httpWebService.doJsonPost(grailsApplication.config.userDetails.url, grailsApplication.config.userDetails.path, "", "")
        } catch (Exception e) {
            log.error "Cache refresh error: " + e.message, e
        }
    }

    private void checkConfig() {
        if (!grailsApplication.config.userDetails.url) {
            log.error "Required config not found: userDetails.url - please add to Config.groovy"
        }
        if (!grailsApplication.config.userDetails.path) {
            log.error "Required config not found: userDetails.path - please add to Config.groovy"
        }
    }

}
