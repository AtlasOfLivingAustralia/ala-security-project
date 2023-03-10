package au.org.ala.web

class AuthTestController {

    def authService

    def index() {
        if (!authService.userInRole(CASRoles.ROLE_ADMIN)) {
            flash.message = "You do not have the required permissions!"
        }
    }

    @AlaSecured(value = CASRoles.ROLE_ADMIN, action = 'index')
    def userList() {
    }

    @AlaSecured(value = CASRoles.ROLE_ADMIN, action = 'index')
    def userDetailsSearch() {
    }

    @AlaSecured(value = CASRoles.ROLE_ADMIN, action = 'index')
    def userSearchResults(String userId) {
        UserDetails user = null
        if (userId) {
            user = authService.getUserForUserId(userId)
        }
        [user: user]
    }

    @AlaSecured(value = CASRoles.ROLE_ADMIN, action = 'index')
    def currentUserDetails() {
    }
}
