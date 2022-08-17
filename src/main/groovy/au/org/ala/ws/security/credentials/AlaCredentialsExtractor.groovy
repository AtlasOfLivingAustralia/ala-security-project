package au.org.ala.ws.security.credentials

import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.credentials.extractor.BearerAuthExtractor
import org.pac4j.core.credentials.extractor.CredentialsExtractor
import org.pac4j.core.credentials.extractor.HeaderExtractor
import org.pac4j.oidc.credentials.OidcCredentials

class AlaCredentialsExtractor implements CredentialsExtractor {

    BearerAuthExtractor bearerAuthExtractor
    HeaderExtractor apiKeyHeaderExtractor

    AlaCredentialsExtractor() {
        bearerAuthExtractor = new BearerAuthExtractor()
    }

    AlaCredentialsExtractor(String apiKeyHeaderName) {
        bearerAuthExtractor = new BearerAuthExtractor()
        apiKeyHeaderExtractor = new HeaderExtractor(apiKeyHeaderName, '')
    }

    @Override
    Optional<Credentials> extract(WebContext context, SessionStore sessionStore) {

        Optional<Credentials> credentials = bearerAuthExtractor.extract(context, sessionStore)
                .map { TokenCredentials tokenCredentials ->

                    OidcCredentials oidcCredentials = new OidcCredentials()
                    oidcCredentials.accessToken = new BearerAccessToken(tokenCredentials.token)

                    oidcCredentials
                }

        if (apiKeyHeaderExtractor && !credentials.isPresent()) {

            credentials = apiKeyHeaderExtractor.extract(context, sessionStore)
                .map { TokenCredentials tokenCredentials -> new AlaApiKeyCredentials(tokenCredentials.token)}
        }

        return credentials
    }
}
