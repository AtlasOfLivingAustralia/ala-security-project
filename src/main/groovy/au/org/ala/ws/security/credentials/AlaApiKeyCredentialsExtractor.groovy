package au.org.ala.ws.security.credentials

import org.pac4j.core.credentials.extractor.HeaderExtractor
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty('security.apikey.enabled')
class AlaApiKeyCredentialsExtractor extends HeaderExtractor {

    AlaApiKeyCredentialsExtractor() {
        headerName = 'apiKey'
        prefixHeader = ''
    }

    @Value('${security.apikey.header.override:apiKey}')
    @Override
    void setHeaderName(String headerName) {
        super.setHeaderName(headerName)
    }
}
