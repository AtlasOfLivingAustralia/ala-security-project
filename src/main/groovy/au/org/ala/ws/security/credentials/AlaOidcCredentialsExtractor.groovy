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
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty('security.jwt.enabled')
class AlaOidcCredentialsExtractor extends BearerAuthExtractor {


    @Override
    Optional<Credentials> extract(WebContext context, SessionStore sessionStore) {

        return super.extract(context, sessionStore)
                .map { TokenCredentials tokenCredentials ->

                    OidcCredentials oidcCredentials = new OidcCredentials()
                    oidcCredentials.accessToken = new BearerAccessToken(tokenCredentials.token)

                    oidcCredentials
                }
    }
}
