package au.org.ala.pac4j.oidc.credentials.extractor;

import org.pac4j.core.context.CallContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.extractor.OidcCredentialsExtractor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * Wrapper for the <code>OidcExtractor</code> to handle the missing state.
 *
 * This occurs if there is an issue after Cognito authentication but before the app callback has processed
 * authentication code and redirected to the secure page.
 * This has proven to be an issue if the user re-clicked on the login button during the callback processing.
 */
public class CognitoOidcExtractor extends OidcCredentialsExtractor {

    static final Logger logger = LoggerFactory.getLogger(CognitoOidcExtractor.class);

    public CognitoOidcExtractor(OidcConfiguration configuration, OidcClient client) {
        super(configuration, client);
    }

    @Override
    public Optional<Credentials> extract(CallContext context) {
        try {
            return super.extract(context);
        } catch (TechnicalException te) {

            if (te.getMessage().equals("State cannot be determined")) {
                logger.error("State not found in session, please check session configuration.");
                // redirect to the authentication page
                throw client.getRedirectionAction(context).get();
            }

            throw te;
        }
    }
}

