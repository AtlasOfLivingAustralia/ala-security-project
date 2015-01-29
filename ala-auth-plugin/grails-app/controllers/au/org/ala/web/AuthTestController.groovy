package au.org.ala.web

class AuthTestController {

    def authService

    def index() {
        if (!authService.userInRole(CASRoles.ROLE_ADMIN)) {
            flash.message = "You do not have the required permissions!"
        }
    }

    def userList() {
        if (!authService.userInRole(CASRoles.ROLE_ADMIN)) {
            redirect(action:'index')
            return
        }
    }

    def userDetailsSearch() {
        if (!authService.userInRole(CASRoles.ROLE_ADMIN)) {
            redirect(action:'index')
            return
        }

    }

    def userSearchResults() {
        if (!authService.userInRole(CASRoles.ROLE_ADMIN)) {
            redirect(action:'index')
            return
        }

        def userId = params.userId as String
        UserDetails user = null
        if (userId) {
            user = authService.getUserForUserId(userId)
        }
        [user: user]
    }

    def currentUserDetails() {
        if (!authService.userInRole(CASRoles.ROLE_ADMIN)) {
            redirect(action:'index')
            return
        }
    }
}
