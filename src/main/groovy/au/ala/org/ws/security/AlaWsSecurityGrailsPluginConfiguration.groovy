package au.ala.org.ws.security



import au.org.ala.ws.security.JwtProperties
import au.org.ala.ws.security.Pac4jProfileManagerHttpRequestWrapperFilter

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
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(JwtProperties)
@ComponentScan('au.org.ala.ws.security')
class AlaWsSecurityGrailsPluginConfiguration {

    static final String JWT_CLIENT = 'JwtClient'

    @Autowired
    JwtProperties jwtProperties

    @Value('${security.apikey.header.override:apiKey}')
    String apiKeyHeader

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
