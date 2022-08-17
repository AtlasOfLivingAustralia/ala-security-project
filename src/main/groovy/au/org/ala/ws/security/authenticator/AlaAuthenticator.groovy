package au.org.ala.ws.security.authenticator

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.authenticator.Authenticator
import org.pac4j.oidc.credentials.OidcCredentials
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

@Component
class AlaAuthenticator implements Authenticator {

    @Autowired(required = true)
    AlaOidcAuthenticator alaOidcAuthenticator

    @Autowired(required = false)
    AlaApiKeyAuthenticator alaApiKeyAuthenticator

    @Override
    void validate(Credentials credentials, WebContext context, SessionStore sessionStore) {

        if (credentials instanceof OidcCredentials) {

            alaOidcAuthenticator.validate(credentials, context, sessionStore)

        } else if (alaApiKeyAuthenticator && credentials instanceof AlaApiKeyAuthenticator) {

            alaApiKeyAuthenticator.validate(credentials, context, sessionStore)
        }
    }
}
