package au.org.ala.web.auth

class AuthTagLib {

    def authService
    def securityPrimitives // gets injected in AlaWebThemeGrailsPlugin 'doWithSpring' section

    static namespace = "auth"
    //static encodeAsForTags = [tagName: 'raw']

    /**
     * Is the user logged in?
     */
    def ifLoggedIn = { attrs, body ->
        if (securityPrimitives.isLoggedIn(request)) out << body()
    }

    /**
     * Is the user not logged in?
     */
    def ifNotLoggedIn = { attrs, body ->
        if (securityPrimitives.isNotLoggedIn(request)) out << body()
    }

    /**
     * Does the currently logged in user have any of the given roles?
     *
     * @attr roles REQUIRED A comma separated list of roles to check
     */
    def ifAnyGranted = { attrs, body ->
        if (securityPrimitives.isAnyGranted(rolesStringToList(attrs))) out << body()
    }

    /**
     * Does the currently logged in user have all of the given roles?
     *
     * @attr roles REQUIRED A comma separated list of roles to check
     */
    def ifAllGranted = { attrs, body ->
        if (securityPrimitives.isAllGranted(rolesStringToList(attrs))) out << body()
    }

    /**
     * Does the currently logged in user have none of the given roles?
     *
     * @attr roles REQUIRED A comma separated list of roles to check
     */
    def ifNotGranted = { attrs, body ->
        if (securityPrimitives.isNotGranted(rolesStringToList(attrs))) out << body()
    }

    private def rolesStringToList(attrs) {
        def roles = attrs.roles ?: ""
        def split = roles.split(",")
        def list = split.toList()
        return list
    }
}
