package au.org.ala.web

import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.engine.SecurityLogic
import org.pac4j.core.http.adapter.HttpActionAdapter
import org.pac4j.core.util.FindBest
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter

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

        if (bestLogic instanceof DefaultSecurityLogic && bestLogic.savedRequestHandler instanceof OverrideSavedRequestHandler) {
            request.setAttribute(OverrideSavedRequestHandler.OVERRIDE_REQUESTED_URL_ATTRIBUTE, redirectUri)
        }

        final WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)

        def result = false

        bestLogic.perform(context, bestSessionStore, config, { ctx, session, profiles, parameters ->
            // if no profiles are loaded, pac4j is not concerned with this request
            result = true
        }, bestAdapter, gateway ? gatewayClients : clients, gateway ? gatewayAuthorizers : authorizers, matchers);
        return result
    }

}
