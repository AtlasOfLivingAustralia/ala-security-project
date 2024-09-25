package au.org.ala.web

import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.engine.SecurityLogic
import org.pac4j.core.http.adapter.HttpActionAdapter
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.jee.util.Pac4JHttpServletRequestWrapper

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class Pac4jSSOStrategy implements SSOStrategy {

    private Config config

    private SecurityLogic securityLogic

    private String clients
    private String gatewayClients

    private String authorizers
    private String gatewayAuthorizers

    private String matchers

    Pac4jSSOStrategy(Config config, SecurityLogic securityLogic, String clients, String gatewayClients, String authorizers, String gatewayAuthorizers, String matchers) {

        this.config = config
        this.securityLogic = securityLogic
        this.clients = clients
        this.gatewayClients = gatewayClients
        this.authorizers = authorizers
        this.gatewayAuthorizers = gatewayAuthorizers
        this.matchers = matchers
    }

    @Override
    boolean authenticate(HttpServletRequest request, HttpServletResponse response, boolean gateway) {
        authenticate(request, response, gateway, null)
    }

    @Override
    boolean authenticate(HttpServletRequest request, HttpServletResponse response, boolean gateway, String redirectUri) {

        def params = new JEEFrameworkParameters(request, response)
//        final SessionStore bestSessionStore = config.getSessionStoreFactory().newSessionStore(params)
//        final HttpActionAdapter bestAdapter = config.httpActionAdapter
        final SecurityLogic bestLogic = this.securityLogic ?: config.securityLogic

        // this is a hack to set the redirectUri in the request so that the OverrideSavedRequestHandler uses it
        // on the return redirect
        if (bestLogic instanceof DefaultSecurityLogic && bestLogic.savedRequestHandler instanceof OverrideSavedRequestHandler) {
            request.setAttribute(OverrideSavedRequestHandler.OVERRIDE_REQUESTED_URL_ATTRIBUTE, redirectUri)
        }

        final WebContext context = config.webContextFactory.newContext(params)

        def result = false

//        config.getSecurityLogic().perform(config, (ctx, session, profiles) -> {
//            // if no profiles are loaded, pac4j is not concerned with this request
//            filterChain.doFilter(profiles.isEmpty() ? request : new Pac4JHttpServletRequestWrapper(request, profiles), response);
//            return null;
//        }, clients, authorizers, matchers, new JEEFrameworkParameters(request, response));

        bestLogic.perform(config, { ctx, session, profiles ->
            // if no profiles are loaded, pac4j is not concerned with this request
            result = true
        }, gateway ? gatewayClients : clients, gateway ? gatewayAuthorizers : authorizers, matchers, params)
        return result
    }

}
