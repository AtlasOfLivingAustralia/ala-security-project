package au.org.ala.web

import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.profile.factory.ProfileManagerFactory
import org.pac4j.core.util.FindBest
import org.pac4j.jee.config.AbstractConfigFilter
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.session.JEESessionStore
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
        def webContext = FindBest.webContextFactory(this.webContextFactory, config, JEEContextFactory.INSTANCE).newContext(request, response)
        def sessionStore = FindBest.sessionStore(this.sessionStore, config, JEESessionStore.INSTANCE)
        def profileManager = FindBest.profileManagerFactory(this.profileManagerFactory, config, ProfileManagerFactory.DEFAULT).apply(webContext, sessionStore)
        profileManager.setConfig(config)

        def existing = WebUtils.getNativeRequest(request, Pac4JHttpServletRequestWrapper)
        def profiles = profileManager.getProfiles()
        chain.doFilter(existing == null && profiles
                ? new Pac4JHttpServletRequestWrapper(request, profiles)
                : request, response)
    }
}
