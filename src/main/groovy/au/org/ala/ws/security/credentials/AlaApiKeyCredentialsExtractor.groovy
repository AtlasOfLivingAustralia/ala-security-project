package au.org.ala.ws.security.credentials

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.extractor.HeaderExtractor

class AlaApiKeyCredentialsExtractor extends HeaderExtractor {

    List<AlaApiKeyCredentialsExtractor> alternativeHeaderExtractors = []

    AlaApiKeyCredentialsExtractor() {
        headerName = 'apiKey'
        prefixHeader = ''
    }

    @Override
    void setHeaderName(String headerName) {
        super.setHeaderName(headerName)
    }

    void setAlternativeHeaderNames(List<String> alternativeHeaderNames) {

        alternativeHeaderExtractors = alternativeHeaderNames.collect { String alternativeHeaderName ->
            AlaApiKeyCredentialsExtractor alternativeHeaderExtractor = new AlaApiKeyCredentialsExtractor()
            alternativeHeaderExtractor.headerName = alternativeHeaderName
            alternativeHeaderExtractor
        }
    }

    @Override
    Optional<Credentials> extract(WebContext context, SessionStore sessionStore) {

        Optional<Credentials> credentials = super.extract(context, sessionStore)

        if (credentials.present) {
            return credentials
        }

        alternativeHeaderExtractors.find { HeaderExtractor alternativeHeaderExtractor ->
            credentials = alternativeHeaderExtractor.extract(context, sessionStore)
            credentials.present
        }

        return credentials
    }
}
