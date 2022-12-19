package au.org.ala.ws.security.authenticator

import au.org.ala.ws.security.ApiKeyClient
import au.org.ala.ws.security.profile.AlaApiUserProfile
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.common.Json
import com.squareup.moshi.Moshi
import com.squareup.moshi.adapters.Rfc3339DateJsonAdapter
import okhttp3.OkHttpClient
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.exception.CredentialsException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import spock.lang.Specification

import static com.github.tomakehurst.wiremock.client.WireMock.get
import static com.github.tomakehurst.wiremock.client.WireMock.post
import static com.github.tomakehurst.wiremock.client.WireMock.okJson
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig

class AlaApiKeyAuthenticatorSpec extends Specification {

    def 'validate apikey'() {

        setup:
        WireMockServer wm = new WireMockServer(wireMockConfig().dynamicPort())
        wm.start()

        Moshi moshi = new Moshi.Builder().add(Date.class, new Rfc3339DateJsonAdapter().nullSafe()).build()

        OkHttpClient.Builder httpClient = new OkHttpClient.Builder()
        ApiKeyClient apiKeyClient = new Retrofit.Builder()
                .baseUrl("http://localhost:${wm.port()}")
                .addConverterFactory(MoshiConverterFactory.create(moshi))
                .client(httpClient.build())
                .build()
                .create(ApiKeyClient)

        AlaApiKeyAuthenticator alaApiKeyAuthenticator = new AlaApiKeyAuthenticator()
        alaApiKeyAuthenticator.apiKeyClient = apiKeyClient

        TokenCredentials alaApiKeyCredentials = new TokenCredentials('testkey')

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        wm.stubFor(
                get(urlEqualTo('/apikey/ws/check?apikey=testkey'))
                        .willReturn(okJson(Json.write([
                                valid: true,
                                userId: "0",
                                email: "email@test.com"
                        ])))
        )

        wm.stubFor(
                post(urlEqualTo('/userdetails/userDetails/getUserDetails?userName=0&includeProps=true'))
                        .willReturn(okJson(Json.write([
                                userId: "0",
                                email: "email@test.com",
                                activated: true,
                                locked: false,
                                firstName: 'given_name',
                                lastName: 'family_name'
                        ])))
        )

        when:
        alaApiKeyAuthenticator.validate(alaApiKeyCredentials, context, sessionStore)

        then:
        alaApiKeyCredentials.userProfile instanceof AlaApiUserProfile
        alaApiKeyCredentials.userProfile.givenName == 'given_name'
        alaApiKeyCredentials.userProfile.familyName == 'family_name'
        alaApiKeyCredentials.userProfile.email == 'email@test.com'
    }

    def 'invalid apikey'() {

        setup:
        WireMockServer wm = new WireMockServer(wireMockConfig().dynamicPort())
        wm.start()

        Moshi moshi = new Moshi.Builder().add(Date.class, new Rfc3339DateJsonAdapter().nullSafe()).build()

        OkHttpClient.Builder httpClient = new OkHttpClient.Builder()
        ApiKeyClient apiKeyClient = new Retrofit.Builder()
                .baseUrl("http://localhost:${wm.port()}")
                .addConverterFactory(MoshiConverterFactory.create(moshi))
                .client(httpClient.build())
                .build()
                .create(ApiKeyClient)

        AlaApiKeyAuthenticator alaApiKeyAuthenticator = new AlaApiKeyAuthenticator()
        alaApiKeyAuthenticator.apiKeyClient = apiKeyClient

        TokenCredentials alaApiKeyCredentials = new TokenCredentials('testkey')

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        wm.stubFor(
                get(urlEqualTo('/apikey/ws/check?apikey=testkey'))
                        .willReturn(okJson(Json.write([
                                valid: false
                        ])))
        )

        when:
        alaApiKeyAuthenticator.validate(alaApiKeyCredentials, context, sessionStore)

        then:
        CredentialsException ce = thrown CredentialsException
        ce.message == 'invalid apiKey: \'testkey\''
    }
}
