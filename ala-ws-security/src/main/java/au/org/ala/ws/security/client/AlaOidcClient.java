package au.org.ala.ws.security.client;

import au.org.ala.ws.security.authenticator.AlaOidcAuthenticator;
import au.org.ala.ws.security.credentials.AlaOidcCredentialsExtractor;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.util.Pac4jConstants;

import java.util.Optional;

public class AlaOidcClient extends AlaDirectClient {
    public AlaOidcClient(AlaOidcCredentialsExtractor alaOidcCredentialsExtractor, AlaOidcAuthenticator alaOidcAuthenticator) {
        getProfileCreator()
        setAuthenticatorIfUndefined(alaOidcAuthenticator);
        setCredentialsExtractorIfUndefined(alaOidcCredentialsExtractor);
    }

    @Override
    protected void internalInit(boolean forceReinit) {
    }

    @Override
    public Optional<Credentials> getCredentials(CallContext ctx) {
        // set the www-authenticate in case of error
        WebContext webContext = ctx.webContext();
        webContext.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, HttpConstants.BEARER_HEADER_PREFIX + "realm=\"" + realmName + "\"");

        return super.getCredentials(ctx);
    }


    public String getRealmName() {
        return realmName;
    }

    public void setRealmName(final String realmName) {
        this.realmName = realmName;
    }

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME;
}
