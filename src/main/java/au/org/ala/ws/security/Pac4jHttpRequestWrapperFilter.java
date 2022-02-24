package au.org.ala.ws.security;

import org.pac4j.core.config.Config;
import org.pac4j.core.context.JEEContextFactory;
import org.pac4j.core.context.WebContextFactory;
import org.pac4j.core.context.session.JEESessionStore;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.factory.ProfileManagerFactory;
import org.pac4j.core.util.FindBest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * HttpFilter that wraps the HttpServletRequest with a pac4j ProfileManager so that it
 * can get user principals, roles, etc from the profile manager.
 */
public class Pac4jHttpRequestWrapperFilter extends HttpFilter {

    private static final Logger log = LoggerFactory.getLogger(Pac4jHttpRequestWrapperFilter.class);
    private Config config;
    private ProfileManager profileManager;

    public Pac4jHttpRequestWrapperFilter(Config config) {
        this.config = config;
    }

    public Pac4jHttpRequestWrapperFilter(Config config, ProfileManager profileManager) {
        this.config = config;
        this.profileManager = profileManager;
    }

    @Override
    protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        // TODO the ProfileManager should pick up existing profiles from eg an interactive login and merge them with a
        //  JWT profile? <- need to check this.
//        var reqWrapperClass = getPac4jWrapperClass();
//        var pac4jRequest = reqWrapperClass != null ? WebUtils.getNativeRequest(req, reqWrapperClass) :  null;
        var sessionStore = FindBest.sessionStore(null, config, JEESessionStore.INSTANCE);
        var webContextFactory = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE);
        var profileManagerFactory = FindBest.profileManagerFactory(null, config, ProfileManagerFactory.DEFAULT);

        chain.doFilter(
                new Pac4jProfileManagerHttpRequestWrapper(
                        req,
                        profileManager != null ?
                                profileManager :
                                profileManagerFactory.apply(webContextFactory.newContext(req, res), sessionStore)),
                res);
    }

    Class<? extends HttpServletRequestWrapper> getPac4jWrapperClass() {
        try {
            return (Class<? extends HttpServletRequestWrapper>) Class.forName("org.pac4j.jee.util.Pac4JHttpServletRequestWrapper");
        } catch (Exception e) {
            log.trace("Couldn't load pac4j http servlet request wrapper", e);
            return null;
        }
    }
}
