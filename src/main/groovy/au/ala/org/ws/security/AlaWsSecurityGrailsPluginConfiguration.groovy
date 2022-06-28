package au.ala.org.ws.security

import au.org.ala.ws.security.JwtAuthenticator
import au.org.ala.ws.security.JwtProperties
import au.org.ala.ws.security.Pac4jProfileManagerHttpRequestWrapperFilter
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jose.util.ResourceRetriever
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import grails.util.Metadata
import org.pac4j.core.authorization.generator.FromAttributesAuthorizationGenerator
import org.pac4j.core.client.Client
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.http.client.direct.DirectBearerAuthClient
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.jee.filter.SecurityFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered

import javax.servlet.DispatcherType

@Configuration
@EnableConfigurationProperties(JwtProperties)
class AlaWsSecurityGrailsPluginConfiguration {

    static final String JWT_CLIENT = 'JwtClient'

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
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    Config pac4jConfig(List<Client> clients, SessionStore sessionStore, WebContextFactory webContextFactory) {
        Config config = new Config(clients)

        config.sessionStore = sessionStore
        config.webContextFactory = webContextFactory
        config
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
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
        def ja = new JwtAuthenticator(oidcProviderMetadata.issuer.toString(), jwtProperties.requiredClaims, oidcProviderMetadata.IDTokenJWSAlgs.toSet(), jwkSource)
        ja.setJwtType(jwtProperties.jwtType)
        return ja
    }

    @Bean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    DirectBearerAuthClient bearerClient(JwtAuthenticator jwtAuthenticator) {
        def client = new DirectBearerAuthClient(jwtAuthenticator)
        client.addAuthorizationGenerator(new FromAttributesAuthorizationGenerator(jwtProperties.roleAttributes,jwtProperties.permissionAttributes))
//        client.addAuthorizationGenerator(new DefaultRolesPermissionsAuthorizationGenerator(['ROLE_USER'] , [])) // client credentials probably doesn't get ROLE_USER?
        client.name = JWT_CLIENT

        client
    }

    @ConditionalOnProperty(prefix= 'security.jwt', name='enabled')
    @Bean
    FilterRegistrationBean pac4jJwtFilter(Config pac4jConfig) {
        final name = 'Pac4j JWT Security Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        SecurityFilter securityFilter = new SecurityFilter(pac4jConfig,
                JWT_CLIENT,
                '', // Equivalent to isAuthenticated
                '') // Matches everything.
        securityFilter.setSecurityLogic(new DefaultSecurityLogic().tap { loadProfilesFromSession = false })
        frb.filter = securityFilter
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 10
        frb.urlPatterns = jwtProperties.urlPatterns
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        return frb
    }

    @Bean
    @ConditionalOnProperty(prefix='security.jwt',name='enabled')
    FilterRegistrationBean pac4jHttpRequestWrapper(Config config) {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean()
        filterRegistrationBean.filter = new Pac4jProfileManagerHttpRequestWrapperFilter(config)
        filterRegistrationBean.order = filterOrder() + 11
        filterRegistrationBean.initParameters = [:]
        filterRegistrationBean.addUrlPatterns('/*')
        filterRegistrationBean
    }

    // The filter chain has to be before grailsWebRequestFilter but after the encoding filter.
    // Its order changed in 3.1 (from Ordered.HIGHEST_PRECEDENCE + 30 (-2147483618) to
    // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 30 (30))
    static int filterOrder() {
        String grailsVersion = Metadata.current.getGrailsVersion()
        if (grailsVersion.startsWith('3.0')) {
            return Ordered.HIGHEST_PRECEDENCE + 21
        }
        else {
            return 21 // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 21
        }
    }

}
