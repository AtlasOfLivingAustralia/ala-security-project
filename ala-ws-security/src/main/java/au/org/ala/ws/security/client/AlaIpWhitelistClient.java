package au.org.ala.ws.security.client;

import au.org.ala.ws.security.authenticator.IpAllowListAuthenticator;
import org.pac4j.http.credentials.extractor.IpExtractor;

public class AlaIpWhitelistClient extends AlaDirectClient {
    public AlaIpWhitelistClient(IpExtractor ipExtractor, IpAllowListAuthenticator alaIpWhitelistAuthenticator) {

        setCredentialsExtractorIfUndefined(ipExtractor);
        setAuthenticatorIfUndefined(alaIpWhitelistAuthenticator);
    }

    @Override
    protected void internalInit(boolean forceReinit) {
    }

}
