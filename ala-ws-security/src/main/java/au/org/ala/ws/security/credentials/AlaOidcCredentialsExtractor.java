package au.org.ala.ws.security.credentials;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.credentials.extractor.BearerAuthExtractor;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.oidc.credentials.OidcCredentials;

import java.util.Optional;

public class AlaOidcCredentialsExtractor extends BearerAuthExtractor {
    @Override
    public Optional<Credentials> extract(CallContext context) {

        try {

            return super.extract(context).map((Credentials tokenCredentials) -> {
                OidcCredentials oidcCredentials = new OidcCredentials();
                oidcCredentials.setAccessTokenObject(new BearerAccessToken(((TokenCredentials)tokenCredentials).getToken()));

                return oidcCredentials;
            });

        } catch (CredentialsException ce) {
            // exception extracting credentials, treat as no credentials to allow pass through
        }


        return Optional.empty();
    }

}
