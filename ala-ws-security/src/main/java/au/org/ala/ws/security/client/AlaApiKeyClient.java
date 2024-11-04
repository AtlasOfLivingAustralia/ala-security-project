package au.org.ala.ws.security.client;

import au.org.ala.ws.security.authenticator.AlaApiKeyAuthenticator;
import au.org.ala.ws.security.credentials.AlaApiKeyCredentialsExtractor;
import org.pac4j.core.client.DirectClient;

public class AlaApiKeyClient extends DirectClient {
    public AlaApiKeyClient(AlaApiKeyCredentialsExtractor alaApiKeyCredentialsExtractor, AlaApiKeyAuthenticator alaApiKeyAuthenticator) {
        setName(alaApiKeyCredentialsExtractor.getClass().getSimpleName());
        setCredentialsExtractorIfUndefined(alaApiKeyCredentialsExtractor);
        setAuthenticatorIfUndefined(alaApiKeyAuthenticator);
    }

    @Override
    protected void internalInit(boolean forceReinit) {
    }

}
