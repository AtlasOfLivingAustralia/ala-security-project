package au.org.ala.ws.security.authenticator

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.web.UserDetails
import au.org.ala.ws.security.ApiKeyClient
import au.org.ala.ws.security.CheckApiKeyResult
import au.org.ala.ws.security.profile.AlaApiUserProfile
import com.squareup.moshi.Moshi
import com.squareup.moshi.adapters.Rfc3339DateJsonAdapter
import okhttp3.OkHttpClient
import org.pac4j.core.context.CallContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.exception.CredentialsException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.mock.Calls
import spock.lang.Specification

class AlaApiKeyAuthenticatorSpec extends Specification {

    def 'validate apikey'() {

        setup:

        ApiKeyClient apiKeyClient = Stub()
        apiKeyClient.checkApiKey('testkey') >> Calls.response(CheckApiKeyResult.valid('0', 'email@test.com'))

        UserDetailsClient userDetailsClient = Stub()
        userDetailsClient.getUserDetails('0', true) >>
                { Calls.response(new UserDetails(0l, "given_name", "family_name", "email@test.com", "email@test.com",
                        "0", false, true, Map.of(), Set.of('ROLE_USER'))) }

        AlaApiKeyAuthenticator alaApiKeyAuthenticator = new AlaApiKeyAuthenticator()
        alaApiKeyAuthenticator.apiKeyClient = apiKeyClient
        alaApiKeyAuthenticator.userDetailsClient = userDetailsClient

        TokenCredentials alaApiKeyCredentials = new TokenCredentials('testkey')

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaApiKeyAuthenticator.validate(new CallContext(context, sessionStore), alaApiKeyCredentials)

        then:
        alaApiKeyCredentials.userProfile instanceof AlaApiUserProfile
        alaApiKeyCredentials.userProfile.givenName == 'given_name'
        alaApiKeyCredentials.userProfile.familyName == 'family_name'
        alaApiKeyCredentials.userProfile.email == 'email@test.com'
    }

    def 'invalid apikey'() {

        setup:
        ApiKeyClient apiKeyClient = Stub()
        apiKeyClient.checkApiKey('testkey') >> Calls.response(CheckApiKeyResult.invalid())

        UserDetailsClient userDetailsClient = Stub()

        AlaApiKeyAuthenticator alaApiKeyAuthenticator = new AlaApiKeyAuthenticator()
        alaApiKeyAuthenticator.apiKeyClient = apiKeyClient
        alaApiKeyAuthenticator.userDetailsClient = userDetailsClient

        TokenCredentials alaApiKeyCredentials = new TokenCredentials('testkey')

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

//        wm.stubFor(
//                get(urlEqualTo('/apikey/ws/check?apikey=testkey'))
//                        .willReturn(okJson(Json.write([
//                                valid: false
//                        ])))
//        )

        when:
        alaApiKeyAuthenticator.validate(new CallContext(context, sessionStore), alaApiKeyCredentials)

        then:
        CredentialsException ce = thrown CredentialsException
        ce.message == 'invalid apiKey: \'testkey\''
    }
}
