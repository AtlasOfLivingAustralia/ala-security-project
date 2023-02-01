package au.org.ala.ws.security.client;

import au.org.ala.ws.security.authenticator.AlaApiKeyAuthenticator;
import au.org.ala.ws.security.credentials.AlaApiKeyCredentialsExtractor;

public class AlaApiKeyClient extends AlaDirectClient {
    public AlaApiKeyClient(AlaApiKeyCredentialsExtractor alaApiKeyCredentialsExtractor, AlaApiKeyAuthenticator alaApiKeyAuthenticator) {

        defaultCredentialsExtractor(alaApiKeyCredentialsExtractor);
        defaultAuthenticator(alaApiKeyAuthenticator);
    }

    @Override
    protected void internalInit(boolean forceReinit) {
    }

}
