package au.org.ala.ws.security

import au.org.ala.ws.security.authenticator.AlaAuthenticator
import au.org.ala.ws.security.credentials.AlaCredentialsExtractor
import org.pac4j.core.client.DirectClient
import org.pac4j.core.context.HttpConstants
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.util.Pac4jConstants
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

import static org.pac4j.core.util.CommonHelper.assertNotBlank

@Component
class AlaAuthClient extends DirectClient {

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME

    @Autowired
    void setAuthenticator(final AlaAuthenticator authenticator) {
        super.setAuthenticator(authenticator)
    }

    @Autowired
    void setCredentialsExtractor(final AlaCredentialsExtractor credentialsExtractor) {
        super.setCredentialsExtractor(credentialsExtractor);
    }


    @Override
    protected void internalInit(boolean forceReinit) {

        assertNotBlank("realmName", this.realmName)

        defaultCredentialsExtractor(new AlaCredentialsExtractor())
    }

    @Override
    protected Optional<Credentials> retrieveCredentials(final WebContext context, final SessionStore sessionStore) {

        // set the www-authenticate in case of error
        context.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, HttpConstants.BEARER_HEADER_PREFIX + "realm=\"" + realmName + "\"");

        try {

            final Optional<Credentials> optCredentials = this.credentialsExtractor.extract(context, sessionStore)

            optCredentials.ifPresent { credentials ->

                final long t0 = System.currentTimeMillis()

                try {
                    this.authenticator.validate(credentials, context, sessionStore)
                } finally {
                    final long t1 = System.currentTimeMillis()
                    logger.debug "Credentials validation took: ${t1 - t0} ms"
                }
            }

            return optCredentials

        } catch (CredentialsException e) {

            logger.info "Failed to retrieve or validate credentials: ${e.message}"
            logger.debug "Failed to retrieve or validate credentials", e

            throw e
        }
    }
}
