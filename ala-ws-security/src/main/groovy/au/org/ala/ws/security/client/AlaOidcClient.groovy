package au.org.ala.ws.security.client

import au.org.ala.ws.security.authenticator.AlaOidcAuthenticator
import au.org.ala.ws.security.credentials.AlaOidcCredentialsExtractor
import org.pac4j.core.context.HttpConstants
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.util.Pac4jConstants

class AlaOidcClient extends AlaDirectClient {

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME

    AlaOidcClient(AlaOidcCredentialsExtractor alaOidcCredentialsExtractor, AlaOidcAuthenticator alaOidcAuthenticator) {

        defaultAuthenticator(alaOidcAuthenticator)
        defaultCredentialsExtractor(alaOidcCredentialsExtractor)
    }

    @Override
    protected void internalInit(boolean forceReinit) {
    }

    @Override
    protected Optional<Credentials> retrieveCredentials(final WebContext context, final SessionStore sessionStore) {
        // set the www-authenticate in case of error
        context.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, HttpConstants.BEARER_HEADER_PREFIX + "realm=\"" + realmName + "\"")

        return super.retrieveCredentials(context, sessionStore)
    }

    String getRealmName() {
        return realmName
    }

    void setRealmName(final String realmName) {
        this.realmName = realmName
    }
}