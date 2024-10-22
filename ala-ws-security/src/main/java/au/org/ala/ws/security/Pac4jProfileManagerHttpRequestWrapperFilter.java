package au.org.ala.ws.security;

import org.pac4j.core.adapter.FrameworkAdapter;
import org.pac4j.core.config.Config;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.jee.context.JEEFrameworkParameters;
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
 * can get user principals, roles, etc from the profile manager.  This is useful if the
 * user profile is created in a Grails interceptor, so request.userPrincipal, etc will work
 * in controllers for JWTs
 */
public class Pac4jProfileManagerHttpRequestWrapperFilter extends HttpFilter {

    private static final Logger log = LoggerFactory.getLogger(Pac4jProfileManagerHttpRequestWrapperFilter.class);
    private Config config;
    private ProfileManager profileManager;

    public Pac4jProfileManagerHttpRequestWrapperFilter(Config config) {
        this.config = config;
    }

    public Pac4jProfileManagerHttpRequestWrapperFilter(Config config, ProfileManager profileManager) {
        this.config = config;
        this.profileManager = profileManager;
    }

    @Override
    protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        // TODO the ProfileManager should pick up existing profiles from eg an interactive login and merge them with a
        //  JWT profile? <- need to check this.
//        var reqWrapperClass = getPac4jWrapperClass();
//        var pac4jRequest = reqWrapperClass != null ? WebUtils.getNativeRequest(req, reqWrapperClass) :  null;
        FrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config);

//        var sessionStore = FindBest.sessionStore(null, config, JEESessionStore.INSTANCE);

//        var webContextFactory = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE);
//        var profileManagerFactory = FindBest.profileManagerFactory(null, config, ProfileManagerFactory.DEFAULT);
        var params = new JEEFrameworkParameters(req, res);
        var profileManagerFactory = config.getProfileManagerFactory();
        var webContextFactory = config.getWebContextFactory();
        var sessionStore = config.getSessionStoreFactory().newSessionStore(params);

        chain.doFilter(
                new Pac4jProfileManagerHttpRequestWrapper(
                        req,
                        profileManager != null ?
                                profileManager :
                                profileManagerFactory.apply(webContextFactory.newContext(params), sessionStore)),
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
