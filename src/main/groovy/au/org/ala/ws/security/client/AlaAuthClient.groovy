package au.org.ala.ws.security.client

import org.pac4j.core.client.BaseClient
import org.pac4j.core.context.HttpConstants
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.exception.http.RedirectionAction
import org.pac4j.core.profile.UserProfile
import org.pac4j.core.util.Pac4jConstants

import static org.pac4j.core.util.CommonHelper.assertNotBlank

class AlaAuthClient extends BaseClient {

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME

    List<AlaDirectClient> authClients

    @Override
    protected void beforeInternalInit(final boolean forceReinit) {
        if (saveProfileInSession == null) {
            saveProfileInSession = false
        }
    }

    @Override
    protected void internalInit(boolean forceReinit) {

        assertNotBlank("realmName", this.realmName)
    }

    @Override
    protected Optional<Credentials> retrieveCredentials(final WebContext context, final SessionStore sessionStore) {

        if (!authClients) {
            return Optional.empty()
        }

        // set the www-authenticate in case of error
        context.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, HttpConstants.BEARER_HEADER_PREFIX + "realm=\"" + realmName + "\"");

        for (BaseClient authClient: authClients) {

                final Optional<Credentials> optCredentials = authClient.getCredentials(context, sessionStore)
                if (optCredentials.present) {

                    return optCredentials
                }
        }

        return Optional.empty()
    }

    @Override
    Optional<RedirectionAction> getRedirectionAction(WebContext context, SessionStore sessionStore) {
        return Optional.empty()
    }

    @Override
    Optional<Credentials> getCredentials(WebContext context, SessionStore sessionStore) {

        init()
        return retrieveCredentials(context, sessionStore)
    }

    @Override
    Optional<RedirectionAction> getLogoutAction(WebContext context, SessionStore sessionStore, UserProfile currentProfile, String targetUrl) {
        return Optional.empty()
    }
}
