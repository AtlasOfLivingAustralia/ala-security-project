package au.org.ala.ws.security.client;

import org.pac4j.core.client.BaseClient;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.core.util.Pac4jConstants;

import java.util.List;
import java.util.Optional;

public class AlaAuthClient extends BaseClient {
    @Override
    protected void beforeInternalInit(final boolean forceReinit) {
        if (saveProfileInSession == null) {
            setSaveProfileInSession(false);
        }

    }

    @Override
    protected void internalInit(boolean forceReinit) {

        CommonHelper.assertNotBlank("realmName", this.realmName);
    }

    @Override
    protected Optional<Credentials> retrieveCredentials(final WebContext context, final SessionStore sessionStore) {

        if (authClients == null || authClients.isEmpty()) {
            return Optional.empty();
        }


        // set the www-authenticate in case of error
        context.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, HttpConstants.BEARER_HEADER_PREFIX + "realm=\"" + realmName + "\"");

        for (BaseClient authClient : authClients) {

            final Optional<Credentials> optCredentials = authClient.getCredentials(context, sessionStore);
            if (optCredentials.isPresent()) {

                return optCredentials;
            }

        }


        return Optional.empty();
    }

    @Override
    public Optional<RedirectionAction> getRedirectionAction(WebContext context, SessionStore sessionStore) {
        return Optional.empty();
    }

    @Override
    public Optional<Credentials> getCredentials(WebContext context, SessionStore sessionStore) {

        init();
        return retrieveCredentials(context, sessionStore);
    }

    @Override
    public Optional<RedirectionAction> getLogoutAction(WebContext context, SessionStore sessionStore, UserProfile currentProfile, String targetUrl) {
        return Optional.empty();
    }

    public List<AlaDirectClient> getAuthClients() {
        return authClients;
    }

    public void setAuthClients(List<AlaDirectClient> authClients) {
        this.authClients = authClients;
    }

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME;
    private List<AlaDirectClient> authClients;
}
