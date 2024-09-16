package au.org.ala.ws.security.client;

import org.pac4j.core.client.DirectClient;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.CredentialsException;

import java.util.Optional;

public abstract class AlaDirectClient extends DirectClient {
    protected Optional<Credentials> internalValidateCredentials(final CallContext ctx, final Credentials credentials) {
        try {
            var newCredentials = this.getAuthenticator().validate(ctx, credentials).orElse(null);
            checkCredentials(ctx, credentials);
            return Optional.ofNullable(newCredentials);
        } catch (CredentialsException e) {
            logger.info("Failed to validate credentials: {}", e.getMessage());
            logger.debug("Failed to validate credentials", e);
//            return Optional.empty();
            throw e; // TODO why?
        }
    }
}