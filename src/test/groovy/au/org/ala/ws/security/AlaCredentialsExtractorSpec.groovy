package au.org.ala.ws.security

import au.org.ala.ws.security.credentials.AlaApiKeyCredentials
import au.org.ala.ws.security.credentials.AlaCredentialsExtractor
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.oidc.credentials.OidcCredentials
import spock.lang.Specification

class AlaCredentialsExtractorSpec extends Specification {

    def 'extract jwt credentials'() {

        setup:
        AlaCredentialsExtractor alaCredentialsExtractor = new AlaCredentialsExtractor()

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
        AlaCredentialsExtractor alaCredentialsExtractor = new AlaCredentialsExtractor('apiKey')

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        Optional<Credentials> credentials = alaCredentialsExtractor.extract(context, sessionStore)

        then:
        1 * context.getRequestHeader('Authorization') >> Optional.empty()
        1 * context.getRequestHeader('authorization') >> Optional.empty()
        1 * context.getRequestHeader('apiKey') >> Optional.of('apiKey')

        credentials.present
        credentials.get() instanceof AlaApiKeyCredentials
        credentials.get().apiKey as String == 'apiKey'
    }
}
