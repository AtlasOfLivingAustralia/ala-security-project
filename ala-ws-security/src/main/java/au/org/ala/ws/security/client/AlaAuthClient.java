package au.org.ala.ws.security.client;

import org.pac4j.core.client.BaseClient;
import org.pac4j.core.client.DirectClient;
import org.pac4j.core.client.IndirectClient;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.http.HttpAction;
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

    public Optional<Credentials> getCredentials(CallContext ctx) {
        this.init();

        try {
            for (BaseClient authClient : authClients) {
                final Optional<Credentials> optCredentials = authClient.getCredentials(ctx);
                if (optCredentials.isPresent()) {
                    Credentials credentials = optCredentials.get();

                    // If credentials already have a profile, validate and return
                    if (credentials.getUserProfile() != null) {
                        this.checkCredentials(ctx, credentials);
                        return Optional.of(credentials);
                    }

                    // DirectBearerAuthClient requires validation and profile resolution
                    Optional<Credentials> optCredWithProfile = authClient.validateCredentials(ctx, credentials);
                    if (optCredWithProfile.isPresent()) {
                        Credentials validatedCredentials = optCredWithProfile.get();

                        // Try to resolve/enrich user profile via profileCreator (e.g. AlaJwtProfileCreator)
                        Optional<UserProfile> userProfile = authClient.getUserProfile(ctx, validatedCredentials);
                        if (userProfile.isPresent()) {
                            validatedCredentials.setUserProfile(userProfile.get());
                        }

                        // As long as the credentials now carry a profile (either from authenticator or profileCreator),
                        // authentication succeeded
                        if (validatedCredentials.getUserProfile() != null) {
                            this.checkCredentials(ctx, validatedCredentials);
                            return Optional.of(validatedCredentials);
                        }
                    }
                    // Validation or profile creation failed for this client; continue to next client
                }
            }
        } catch (CredentialsException e) {
            this.logger.info("Failed to retrieve credentials: {}", e.getMessage());
            this.logger.debug("Failed to retrieve credentials", e);
        }
        return Optional.empty();
    }

    @Override
    public HttpAction processLogout(CallContext callContext, Credentials credentials) {
        this.init();
        // TODO This is probably wrong
        for (BaseClient authClient : authClients) {
            if (authClient instanceof IndirectClient) {
                final HttpAction action = ((IndirectClient) authClient).processLogout(callContext, credentials);
                if (action != null) {
                    return action;
                }
            }
        }
        throw new UnsupportedOperationException("Direct clients cannot process logout");
    }

    @Override
    public Optional<RedirectionAction> getRedirectionAction(CallContext callContext) {
        return Optional.empty();
    }

    @Override
    public Optional<RedirectionAction> getLogoutAction(CallContext callContext, UserProfile userProfile, String s) {
        return Optional.empty();
    }

    public List<DirectClient> getAuthClients() {
        return authClients;
    }

    public void setAuthClients(List<DirectClient> authClients) {
        this.authClients = authClients;
    }

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME;
    private List<DirectClient> authClients;
}
