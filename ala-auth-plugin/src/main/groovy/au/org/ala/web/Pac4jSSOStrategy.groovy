package au.org.ala.web

import org.pac4j.core.config.Config
import org.pac4j.core.context.JEEContextFactory
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.JEESessionStore
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.engine.SecurityLogic
import org.pac4j.core.engine.savedrequest.DefaultSavedRequestHandler
import org.pac4j.core.http.adapter.HttpActionAdapter
import org.pac4j.core.http.adapter.JEEHttpActionAdapter
import org.pac4j.core.util.FindBest

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

        final SessionStore bestSessionStore = FindBest.sessionStore(null, config, JEESessionStore.INSTANCE)
        final HttpActionAdapter bestAdapter = FindBest.httpActionAdapter(null, config, JEEHttpActionAdapter.INSTANCE)
        final SecurityLogic bestLogic = FindBest.securityLogic(securityLogic, config, DefaultSecurityLogic.INSTANCE)

        if (bestLogic instanceof DefaultSecurityLogic) {
            bestLogic.savedRequestHandler = new OverrideSavedRequestHandler(redirectUri: redirectUri)
        }

        final WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)

        def result = true

        bestLogic.perform(context, bestSessionStore, config, { ctx, session, profiles, parameters ->
            // if no profiles are loaded, pac4j is not concerned with this request
            result = false
        }, bestAdapter, gateway ? gatewayClients : clients, gateway ? gatewayAuthorizers : authorizers, matchers);
        return result
    }

    static class OverrideSavedRequestHandler extends DefaultSavedRequestHandler {

        String redirectUri

        protected String getRequestedUrl(final WebContext context, final SessionStore sessionStore) {
            return redirectUri ?: context.getFullRequestURL()
        }
    }
}
