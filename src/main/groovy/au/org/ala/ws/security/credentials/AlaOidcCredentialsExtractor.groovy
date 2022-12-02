package au.org.ala.ws.security.credentials

import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.credentials.extractor.BearerAuthExtractor
import org.pac4j.core.exception.CredentialsException
import org.pac4j.oidc.credentials.OidcCredentials
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

class AlaOidcCredentialsExtractor extends BearerAuthExtractor {

    @Override
    Optional<Credentials> extract(WebContext context, SessionStore sessionStore) {

        try {

            return super.extract(context, sessionStore)
                    .map { TokenCredentials tokenCredentials ->

                        OidcCredentials oidcCredentials = new OidcCredentials()
                        oidcCredentials.accessToken = new BearerAccessToken(tokenCredentials.token)

                        oidcCredentials
                    }

        } catch (CredentialsException ce) {
            // exception extracting credentials, treat as no credentials to allow pass through
        }

        return Optional.empty()
    }
}
