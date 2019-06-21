package au.org.ala.web

class BootStrap {

    def grailsApplication

    def init = { servletContext ->
        def cookieName = grailsApplication.config.security.cas.authCookieName
        if (cookieName) {
            System.setProperty('ala.auth.cookie.name',  cookieName)
        }
    }
    def destroy = {
    }
}
