package au.org.ala.web

class BootStrap {

    def grailsApplication

    def init = { servletContext ->
        // hack to load the auth cookie name into a system property from the grails config properties before the
        // AuthenticationCookieUtils static initializer runs
        def config = grailsApplication.config

        def cookieName = config.getProperty('security.core.auth-cookie-name') ?: config.getProperty('security.core.authCookieName') ?: config.getProperty('security.cas.authCookieName')
        if (cookieName) {
            System.setProperty('ala.auth.cookie.name', cookieName)
        }
    }
    def destroy = {
    }
}
