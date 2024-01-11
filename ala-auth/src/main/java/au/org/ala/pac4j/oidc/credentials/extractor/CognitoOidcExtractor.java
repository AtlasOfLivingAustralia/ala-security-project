package au.org.ala.pac4j.oidc.credentials.extractor;

import org.pac4j.core.client.IndirectClient;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.extractor.OidcExtractor;

import java.util.Optional;

/**
 * Wrapper for the <code>OidcExtractor</code> to handle the missing state.
 *
 * This occurs if there is an issue after Cognito authentication but before the app callback has processed
 * authentication code and redirected to the secure page.
 * This has proven to be an issue if the user re-clicked on the login button during the callback processing.
 */
public class CognitoOidcExtractor extends OidcExtractor {

    public CognitoOidcExtractor(OidcConfiguration configuration, OidcClient client) {
        super(configuration, client);
    }

    @Override
    public Optional<Credentials> extract(WebContext context, SessionStore sessionStore) {
        try {
            return super.extract(context, sessionStore);
        } catch (TechnicalException te) {

            if (te.getMessage().equals("State cannot be determined")) {

//                sessionStore.set(context, Pac4jConstants.REQUESTED_URL, requestedUrl);
                // redirect to the authentication page
                throw client.getRedirectionAction(context, sessionStore).get();
            }

            throw te;
        }
    }
}

