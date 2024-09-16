package au.org.ala.web

import org.pac4j.core.adapter.FrameworkAdapter
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.profile.factory.ProfileManagerFactory
import org.pac4j.jee.config.AbstractConfigFilter
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.jee.util.Pac4JHttpServletRequestWrapper
import org.springframework.web.util.WebUtils

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Loads existing Pac4J profiles from the Http Session and, if they are present and the
 * request is not already wrapped (ie has already authenticated a user), wraps the request
 * in a Pac4JHttpServletRequestWrapper with the existing profiles.
 */
class Pac4jHttpServletRequestWrapperFilter extends AbstractConfigFilter {

    WebContextFactory webContextFactory
    SessionStore sessionStore
    ProfileManagerFactory profileManagerFactory

    Pac4jHttpServletRequestWrapperFilter(Config config, SessionStore sessionStore, WebContextFactory webContextFactory) {
        this.config = config
        this.sessionStore = sessionStore
        this.webContextFactory = webContextFactory
    }

    @Override
    protected void internalFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        FrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config)

        def params = new JEEFrameworkParameters(request, response)
        def webContext = this.webContextFactory.newContext(params) ?: config.getWebContextFactory().newContext(params)
        def sessionStore = this.sessionStore ?: config.getSessionStoreFactory().newSessionStore(params)
        def profileManager = (this.profileManagerFactory ?: config.getProfileManagerFactory()).apply(webContext, sessionStore)
        profileManager.setConfig(config)

        def existing = WebUtils.getNativeRequest(request, Pac4JHttpServletRequestWrapper)
        def profiles = profileManager.getProfiles()
        chain.doFilter(existing == null && profiles
                ? new Pac4JHttpServletRequestWrapper(request, profiles)
                : request, response)
    }
}
