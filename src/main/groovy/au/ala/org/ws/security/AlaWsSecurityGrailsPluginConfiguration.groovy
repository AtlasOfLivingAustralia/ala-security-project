package au.ala.org.ws.security

import au.org.ala.ws.security.JwtAuthenticator
import au.org.ala.ws.security.JwtProperties
import au.org.ala.ws.security.Pac4jHttpRequestWrapperFilter
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jose.util.ResourceRetriever
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.pac4j.core.config.Config
import org.pac4j.core.context.JEEContextFactory
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.JEESessionStore
import org.pac4j.core.context.session.SessionStore
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(JwtProperties)
class AlaWsSecurityGrailsPluginConfiguration {

    @Autowired
    JwtProperties jwtProperties


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
    Config pac4jConfig(SessionStore sessionStore, WebContextFactory webContextFactory) {
        Config config = new Config()

        config.sessionStore = sessionStore
        config.webContextFactory = webContextFactory
        config
    }

    @Bean
    @ConditionalOnMissingBean
    ResourceRetriever resourceRetriever() {
        new DefaultResourceRetriever(jwtProperties.connectTimeoutMs, jwtProperties.readTimeoutMs);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    OIDCProviderMetadata oidcProviderMetadata(ResourceRetriever resourceRetriever) {
        OIDCProviderMetadata.parse(resourceRetriever.retrieveResource(jwtProperties.discoveryUri.toURL()).getContent())
    }

    @Bean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    JWKSource<SecurityContext> jwkSource(OIDCProviderMetadata oidcProviderMetadata, ResourceRetriever resourceRetriever) {
        return new RemoteJWKSet(oidcProviderMetadata.JWKSetURI.toURL(), resourceRetriever)
    }


    @Bean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    JwtAuthenticator jwtAuthenticator(OIDCProviderMetadata oidcProviderMetadata, JWKSource<SecurityContext> jwkSource) {
        def ja = new JwtAuthenticator(oidcProviderMetadata.issuer.toString(), oidcProviderMetadata.IDTokenJWSAlgs.toSet(), jwkSource)
        ja.setJwtType(jwtProperties.jwtType)
        return ja
    }

    @Bean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    FilterRegistrationBean pac4jHttpRequestWrapper() {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean()
        filterRegistrationBean.filter = new Pac4jHttpRequestWrapperFilter()
        filterRegistrationBean.initParameters = [:]
        filterRegistrationBean.addUrlPatterns('/*')
        filterRegistrationBean
    }

}
