package au.org.ala.ws.security.client

import au.org.ala.ws.security.authenticator.AlaIpWhitelistAuthenticator
import au.org.ala.ws.security.credentials.AlaIpExtractor
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component

class AlaIpWhitelistClient extends AlaDirectClient {

    AlaIpWhitelistClient(AlaIpExtractor alaIpExtractor, AlaIpWhitelistAuthenticator alaIpWhitelistAuthenticator) {

        defaultCredentialsExtractor(alaIpExtractor)
        defaultAuthenticator(alaIpWhitelistAuthenticator)
    }

    @Override
    protected void internalInit(boolean forceReinit) {}
}
