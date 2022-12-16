package au.org.ala.ws.security.client

import org.pac4j.core.client.DirectClient
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.exception.CredentialsException

abstract class AlaDirectClient extends DirectClient {

    @Override
    protected Optional<Credentials> retrieveCredentials(final WebContext context, final SessionStore sessionStore) {
        try {
            final var optCredentials = this.credentialsExtractor.extract(context, sessionStore)
            optCredentials.ifPresent {credentials ->
                final var t0 = System.currentTimeMillis()
                try {
                    this.authenticator.validate(credentials, context, sessionStore);
                } finally {
                    final var t1 = System.currentTimeMillis()
                    logger.debug("Credentials validation took: {} ms", t1 - t0)
                }
            }
            return optCredentials
        } catch (CredentialsException e) {
            logger.info("Failed to retrieve or validate credentials: {}", e.getMessage())
            logger.debug("Failed to retrieve or validate credentials", e)

            throw e
        }
    }
}