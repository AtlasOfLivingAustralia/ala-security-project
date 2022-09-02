package au.org.ala.ws.security.client

import au.org.ala.ws.security.authenticator.AlaApiKeyAuthenticator
import au.org.ala.ws.security.credentials.AlaApiKeyCredentialsExtractor
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component

@Component
@Order(20)
@ConditionalOnProperty('security.apikey.enabled')
class AlaApiKeyClient extends AlaDirectClient {


    AlaApiKeyClient(AlaApiKeyCredentialsExtractor alaApiKeyCredentialsExtractor, AlaApiKeyAuthenticator alaApiKeyAuthenticator) {

        defaultCredentialsExtractor(alaApiKeyCredentialsExtractor)
        defaultAuthenticator(alaApiKeyAuthenticator)
    }

    @Override
    protected void internalInit(boolean forceReinit) {}
}
