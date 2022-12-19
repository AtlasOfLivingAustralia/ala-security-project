package au.org.ala.ws.security.client;

import org.pac4j.core.client.DirectClient;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.CredentialsException;

import java.util.Optional;

public abstract class AlaDirectClient extends DirectClient {
    @Override
    protected Optional<Credentials> retrieveCredentials(final WebContext context, final SessionStore sessionStore) {
        try {
            final Optional<Credentials> optCredentials = this.getCredentialsExtractor().extract(context, sessionStore);
            optCredentials.ifPresent( credentials -> {
                    final long t0 = System.currentTimeMillis();
                    try {
                        AlaDirectClient.this.getAuthenticator().validate(credentials, context, sessionStore);
                    } finally {
                        final long t1 = System.currentTimeMillis();
                        logger.debug("Credentials validation took: {} ms", t1 - t0);
                    }

            });
            return optCredentials;
        } catch (CredentialsException e) {
            logger.info("Failed to retrieve or validate credentials: {}", e.getMessage());
            logger.debug("Failed to retrieve or validate credentials", e);

            throw e;
        }
    }
}