package au.org.ala.ws.security.client;

import au.org.ala.ws.security.authenticator.AlaIpWhitelistAuthenticator;
import org.pac4j.http.credentials.extractor.IpExtractor;

public class AlaIpWhitelistClient extends AlaDirectClient {
    public AlaIpWhitelistClient(IpExtractor ipExtractor, AlaIpWhitelistAuthenticator alaIpWhitelistAuthenticator) {

        defaultCredentialsExtractor(ipExtractor);
        defaultAuthenticator(alaIpWhitelistAuthenticator);
    }

    @Override
    protected void internalInit(boolean forceReinit) {
    }

}
