package au.org.ala.ws.security

import au.org.ala.ws.security.credentials.AlaApiKeyCredentials
import au.org.ala.ws.security.credentials.AlaApiKeyCredentialsExtractor
import au.org.ala.ws.security.credentials.AlaOidcCredentialsExtractor
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.oidc.credentials.OidcCredentials
import spock.lang.Specification

class AlaCredentialsExtractorSpec extends Specification {

    def 'extract jwt credentials'() {

        setup:
        AlaOidcCredentialsExtractor alaCredentialsExtractor = new AlaOidcCredentialsExtractor()

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        Optional<Credentials> credentials = alaCredentialsExtractor.extract(context, sessionStore)

        then:
        1 * context.getRequestHeader('Authorization') >> Optional.of('Bearer auth_token')

        credentials.present
        credentials.get() instanceof OidcCredentials
        credentials.get().accessToken as String == 'auth_token'

        when:
        credentials = alaCredentialsExtractor.extract(context, sessionStore)

        then:
        _ * context.getRequestHeader(_) >> Optional.empty()

        !credentials.present
    }

    def 'extract apiKey credentials'() {

        setup:
        AlaApiKeyCredentialsExtractor alaCredentialsExtractor = new AlaApiKeyCredentialsExtractor()

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        Optional<Credentials> credentials = alaCredentialsExtractor.extract(context, sessionStore)

        then:
        1 * context.getRequestHeader('apiKey') >> Optional.of('apiKey')

        credentials.present
        credentials.get() instanceof TokenCredentials
        credentials.get().token as String == 'apiKey'
    }
}
