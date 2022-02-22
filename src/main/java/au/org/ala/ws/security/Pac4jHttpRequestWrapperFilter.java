package au.org.ala.ws.security;

import org.pac4j.core.context.session.JEESessionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Pac4jHttpRequestWrapperFilter extends HttpFilter {

    private static Logger log = LoggerFactory.getLogger(Pac4jHttpRequestWrapperFilter.class);

    @Override
    protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        // If there is a Pac4jHttpServletRequestWrapper then pac4j has authenticated this session / request as well,
        // so there's already a user session.
        // Blindly adding the GrailsPac4jHttpRequestWrapper will hide the existing Pac4j Profiles in the request
        // TODO the ProfileManager may actually pick up existing profiles and merge them with a JWT profile? <- need to check this.
        var reqWrapperClass = getPac4jWrapperClass();
        var pac4jRequest = reqWrapperClass != null ? WebUtils.getNativeRequest(req, reqWrapperClass) :  null;
        chain.doFilter(pac4jRequest != null ? pac4jRequest : new GrailsPac4jHttpRequestWrapper(req, res, JEESessionStore.INSTANCE), res);
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
