package au.org.ala.ws.config

import au.org.ala.web.Pac4jContextProvider
import au.org.ala.ws.tokens.TokenClient
import au.org.ala.ws.tokens.TokenInterceptor
import au.org.ala.ws.tokens.TokenService
import okhttp3.Interceptor
import org.pac4j.core.config.Config
import org.pac4j.core.context.session.SessionStore
import org.pac4j.oidc.config.OidcConfiguration
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class AlaWsPluginConfig {

    @Value('${security.oidc.scopes:openid}')
    String oidcScopes

    @Value('${webservice.jwt-scopes:openid}')
    String jwtScopes

    @Value('${webservices.cache-tokens:true}')
    boolean cacheTokens

    @Bean
    TokenClient tokenClient(
            @Autowired(required = false) OidcConfiguration oidcConfiguration
    ) {
        new TokenClient(oidcConfiguration)
    }

    @Bean
    TokenService tokenService(
            @Autowired(required = false) Config config,
            @Autowired(required = false) OidcConfiguration oidcConfiguration,
            @Autowired(required = false) Pac4jContextProvider pac4jContextProvider,
            @Autowired(required = false) SessionStore sessionStore,
            @Autowired TokenClient tokenClient
    ) {
        new TokenService(config, oidcConfiguration, pac4jContextProvider,
                sessionStore, tokenClient, oidcScopes, jwtScopes, cacheTokens)
    }

    /**
     * OK HTTP Interceptor that injects a client credentials Bearer token into a request
     * @return
     */
    @ConditionalOnProperty(prefix='webservice', name ='jwt')
    @ConditionalOnMissingBean
    @Bean
    Interceptor jwtInterceptor(@Autowired TokenService tokenService) {
        new TokenInterceptor(tokenService)
    }
}
