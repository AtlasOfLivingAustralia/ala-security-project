package au.org.ala.ws.config

import au.org.ala.web.Pac4jContextProvider
import au.org.ala.ws.tokens.TokenClient
import au.org.ala.ws.tokens.TokenInterceptor
import au.org.ala.ws.tokens.TokenService
import okhttp3.Interceptor
import org.pac4j.core.config.Config
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.context.session.SessionStoreFactory
import org.pac4j.oidc.config.OidcConfiguration
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

import javax.annotation.PostConstruct

@Configuration
class AlaWsPluginConfig {

    @Value('${webservice.client-id}')
    String clientId

    @Value('${webservice.client-secret}')
    String clientSecret

    @Value('${webservice.jwt-scopes}')
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
            @Autowired(required = false) OidcConfiguration oidcConfiguration,
            @Autowired(required = false) SessionStoreFactory sessionStoreFactory,
            @Autowired TokenClient tokenClient
    ) {
        // note not injecting PAC4j Config here due to potential circular dependency
        new TokenService(oidcConfiguration,
                sessionStoreFactory, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens)
    }



    /**
     * OK HTTP Interceptor that injects a client credentials Bearer token into a request
     * @return
     */
    @ConditionalOnProperty(prefix='webservice', name ='jwt')
    @ConditionalOnMissingBean(name = "jwtInterceptor")
    @Bean
    TokenInterceptor jwtInterceptor(@Autowired TokenService tokenService) {
        new TokenInterceptor(tokenService)
    }
}
