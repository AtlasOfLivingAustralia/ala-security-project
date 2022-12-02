package au.ala.org.ws.security

import au.org.ala.ws.security.ApiKeyClient
import au.org.ala.ws.security.ApiKeyProperties
import au.org.ala.ws.security.IpWhitelistProperties
import au.org.ala.ws.security.JwtProperties
import au.org.ala.ws.security.Pac4jProfileManagerHttpRequestWrapperFilter
import au.org.ala.ws.security.authenticator.AlaApiKeyAuthenticator
import au.org.ala.ws.security.authenticator.AlaIpWhitelistAuthenticator
import au.org.ala.ws.security.authenticator.AlaOidcAuthenticator
import au.org.ala.ws.security.client.AlaApiKeyClient
import au.org.ala.ws.security.client.AlaAuthClient
import au.org.ala.ws.security.client.AlaDirectClient
import au.org.ala.ws.security.client.AlaIpWhitelistClient
import au.org.ala.ws.security.client.AlaOidcClient
import au.org.ala.ws.security.credentials.AlaApiKeyCredentialsExtractor
import au.org.ala.ws.security.credentials.AlaIpExtractor
import au.org.ala.ws.security.credentials.AlaOidcCredentialsExtractor
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.squareup.moshi.Moshi
import com.squareup.moshi.adapters.Rfc3339DateJsonAdapter
import retrofit2.converter.moshi.MoshiConverterFactory
import okhttp3.OkHttpClient
import org.pac4j.core.authorization.generator.FromAttributesAuthorizationGenerator
import org.pac4j.core.client.Client
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.SessionStore
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.oidc.config.OidcConfiguration
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import retrofit2.Retrofit

@Configuration
@EnableConfigurationProperties([ JwtProperties, ApiKeyProperties, IpWhitelistProperties ])
class AlaWsSecurityGrailsPluginConfiguration {

    static final String JWT_CLIENT = 'JwtClient'

    @Autowired
    JwtProperties jwtProperties

    @Autowired
    ApiKeyProperties apiKeyProperties

    @Autowired
    IpWhitelistProperties ipWhitelistProperties

    @Bean
    @ConditionalOnMissingBean
    SessionStore sessionStore() {
        JEESessionStore.INSTANCE
    }

    @Bean
    @ConditionalOnMissingBean
    WebContextFactory webContextFactory() {
        JEEContextFactory.INSTANCE
    }

    @Bean
    @ConditionalOnMissingBean
    Config pac4jConfig(List<Client> clients, SessionStore sessionStore, WebContextFactory webContextFactory) {
        Config config = new Config(clients)

        config.sessionStore = sessionStore
        config.webContextFactory = webContextFactory
        config
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    OidcConfiguration oidcConfiguration() {

        OidcConfiguration oidcConfig = new OidcConfiguration()
        oidcConfig.discoveryURI = jwtProperties.discoveryUri
        oidcConfig.clientId = jwtProperties.clientId
        oidcConfig.connectTimeout = jwtProperties.connectTimeoutMs
        oidcConfig.readTimeout = jwtProperties.readTimeoutMs

        return oidcConfig
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty('security.jwt.enabled')
    AlaOidcClient getAlaOidcClient(OidcConfiguration oidcConfiguration) {

        AlaOidcCredentialsExtractor credentialsExtractor = new AlaOidcCredentialsExtractor()

        AlaOidcAuthenticator authenticator = new AlaOidcAuthenticator(oidcConfiguration)
        authenticator.issuer = oidcConfiguration.findProviderMetadata().issuer
        authenticator.expectedJWSAlgs = oidcConfiguration.findProviderMetadata().IDTokenJWSAlgs.toSet()
        authenticator.keySource = new RemoteJWKSet(oidcConfiguration.findProviderMetadata().JWKSetURI.toURL(), oidcConfiguration.findResourceRetriever())
        authenticator.authorizationGenerator = new FromAttributesAuthorizationGenerator(jwtProperties.roleAttributes, jwtProperties.permissionAttributes)

        authenticator.requiredClaims = jwtProperties.requiredClaims
        authenticator.requiredScopes = jwtProperties.requiredScopes

        authenticator.accessTokenRoleClaims = jwtProperties.accessTokenRoles
        authenticator.rolePrefix = jwtProperties.rolePrefix
        authenticator.roleToUppercase = jwtProperties.roleToUppercase

        return new AlaOidcClient(credentialsExtractor, authenticator)
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty('security.apikey.enabled')
    AlaApiKeyClient getAlaApiKeyClient() {

        AlaApiKeyCredentialsExtractor credentialsExtractor = new AlaApiKeyCredentialsExtractor()
        credentialsExtractor.headerName = apiKeyProperties.header.override
        credentialsExtractor.alternativeHeaderNames = apiKeyProperties.header.alternatives

        Moshi moshi = new Moshi.Builder().add(Date.class, new Rfc3339DateJsonAdapter().nullSafe()).build()

        OkHttpClient.Builder httpClient = new OkHttpClient.Builder()
        ApiKeyClient apiKeyClient = new Retrofit.Builder()
                .baseUrl(apiKeyProperties.auth.serviceUrl)
                .addConverterFactory(MoshiConverterFactory.create(moshi))
                .client(httpClient.build())
                .build()
                .create(ApiKeyClient)

        AlaApiKeyAuthenticator authenticator = new AlaApiKeyAuthenticator()
        authenticator.apiKeyClient = apiKeyClient

        return new AlaApiKeyClient(credentialsExtractor, authenticator)
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty('security.ip.whitelist')
    AlaIpWhitelistClient getAlaIpWhitelistClient() {

        AlaIpExtractor credentialsExtractor = new AlaIpExtractor()

        AlaIpWhitelistAuthenticator authenticator = new AlaIpWhitelistAuthenticator()
        authenticator.ipWhitelist = ipWhitelistProperties.whitelist

        return new AlaIpWhitelistClient(credentialsExtractor, authenticator)
    }

    @Bean
    @ConditionalOnMissingBean
    AlaAuthClient getAlaAuthClient(List<AlaDirectClient> authClients) {

        AlaAuthClient authClient = new AlaAuthClient()
        authClient.authClients = authClients

        return authClient
    }

    @Bean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    FilterRegistrationBean pac4jHttpRequestWrapper(Config config) {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean()
        filterRegistrationBean.filter = new Pac4jProfileManagerHttpRequestWrapperFilter(config)
        filterRegistrationBean.order = filterOrder() + 6 // This is to place this filter after the request wrapper filter in the ala-auth-plugin
        filterRegistrationBean.initParameters = [:]
        filterRegistrationBean.addUrlPatterns('/*')
        filterRegistrationBean
    }

    static int filterOrder() {

        return 21 // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 21
    }

}
