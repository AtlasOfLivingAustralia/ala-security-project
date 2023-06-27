package au.org.ala.ws.security;

import au.org.ala.userdetails.UserDetailsClient;
import au.org.ala.ws.security.authenticator.AlaApiKeyAuthenticator;
import au.org.ala.ws.security.authenticator.AlaIpWhitelistAuthenticator;
import au.org.ala.ws.security.authenticator.AlaOidcAuthenticator;
import au.org.ala.ws.security.client.AlaApiKeyClient;
import au.org.ala.ws.security.client.AlaAuthClient;
import au.org.ala.ws.security.client.AlaDirectClient;
import au.org.ala.ws.security.client.AlaIpWhitelistClient;
import au.org.ala.ws.security.client.AlaOidcClient;
import au.org.ala.ws.security.credentials.AlaApiKeyCredentialsExtractor;
import au.org.ala.ws.security.credentials.AlaOidcCredentialsExtractor;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.ehcache.Cache;
import org.ehcache.config.CacheConfiguration;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.config.builders.ExpiryPolicyBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;
import org.pac4j.core.authorization.generator.FromAttributesAuthorizationGenerator;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContextFactory;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.profile.creator.ProfileCreator;
import org.pac4j.http.credentials.extractor.IpExtractor;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.session.JEESessionStore;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.ehcache.EhCacheCacheManager;
import org.springframework.cache.jcache.JCacheCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableConfigurationProperties({JwtProperties.class, ApiKeyProperties.class, IpWhitelistProperties.class})
public class AlaWsSecurityConfiguration {

    private static final String JWT_CLIENT = "JwtClient";
    @Autowired
    private JwtProperties jwtProperties;
    @Autowired
    private ApiKeyProperties apiKeyProperties;
    @Autowired
    private IpWhitelistProperties ipWhitelistProperties;

    @Value("${info.app.name:Unknown-App}")
    String name;
    @Value("${info.app.version:1}")
    String version;

    @Bean
    @ConditionalOnMissingBean
    public SessionStore sessionStore() {
        return JEESessionStore.INSTANCE;
    }

    @Bean
    @ConditionalOnMissingBean
    public WebContextFactory webContextFactory() {
        return JEEContextFactory.INSTANCE;
    }

    @Bean
    @ConditionalOnMissingBean
    public Config pac4jConfig(List<Client> clients, SessionStore sessionStore, WebContextFactory webContextFactory) {
        Config config = new Config(clients);

        config.setSessionStore(sessionStore);
        config.setWebContextFactory(webContextFactory);
        return config;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security.jwt", name="enabled")
    public ResourceRetriever jwtResourceRetriever() {
        DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(jwtProperties.getConnectTimeoutMs(), jwtProperties.getReadTimeoutMs());
        String userAgent = name+"/"+version;
        resourceRetriever.setHeaders(Map.of(HttpHeaders.USER_AGENT, List.of(userAgent)));
        return resourceRetriever;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security.jwt", name = "enabled")
    public OidcConfiguration oidcConfiguration(ResourceRetriever jwtResourceRetriever) {

        OidcConfiguration oidcConfig = new OidcConfiguration();
        oidcConfig.setDiscoveryURI(jwtProperties.getDiscoveryUri());
        oidcConfig.setClientId(jwtProperties.getClientId());
        oidcConfig.setConnectTimeout(jwtProperties.getConnectTimeoutMs());
        oidcConfig.setReadTimeout(jwtProperties.getReadTimeoutMs());

        oidcConfig.setResourceRetriever(jwtResourceRetriever);

        return oidcConfig;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security.jwt", name = "enabled")
    JWKSource<SecurityContext> jwkSource(OidcConfiguration oidcConfiguration) {
        OIDCProviderMetadata providerMetadata = oidcConfiguration.findProviderMetadata();
        URL keySourceUrl;
        try {
            keySourceUrl = providerMetadata.getJWKSetURI().toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException("shouldn't happen", e);
        }
        return new RemoteJWKSet<>(keySourceUrl, oidcConfiguration.findResourceRetriever());
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("security.jwt.enabled")
    public AlaOidcClient getAlaOidcClient(OidcConfiguration oidcConfiguration, JWKSource<SecurityContext> jwkSource, CacheManager cacheManager) {

        AlaOidcCredentialsExtractor credentialsExtractor = new AlaOidcCredentialsExtractor();
        ProfileCreator profileCreator = new OidcProfileCreator(oidcConfiguration, new OidcClient());

        AlaOidcAuthenticator authenticator = new AlaOidcAuthenticator(oidcConfiguration, profileCreator);
        OIDCProviderMetadata providerMetadata = oidcConfiguration.findProviderMetadata();
        authenticator.setIssuer(providerMetadata.getIssuer());
        authenticator.setExpectedJWSAlgs(Set.copyOf(providerMetadata.getIDTokenJWSAlgs()));

        authenticator.setKeySource(jwkSource);
        authenticator.setAuthorizationGenerator(new FromAttributesAuthorizationGenerator(jwtProperties.getRoleClaims(), jwtProperties.getPermissionClaims()));

        authenticator.setUserIdClaim(jwtProperties.getUserIdClaim());
        authenticator.setRequiredClaims(jwtProperties.getRequiredClaims());
        authenticator.setRequiredScopes(jwtProperties.getRequiredScopes());

        authenticator.setRolesFromAccessToken(jwtProperties.isRolesFromAccessToken());
        if (authenticator.isRolesFromAccessToken()) {
            authenticator.setAccessTokenRoleClaims(jwtProperties.getRoleClaims());
        }

        authenticator.setRolePrefix(jwtProperties.getRolePrefix());
        authenticator.setRoleToUppercase(jwtProperties.isRoleToUppercase());

        authenticator.setCacheManager(cacheManager);

        return new AlaOidcClient(credentialsExtractor, authenticator);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security.apikey", name = "enabled")
    public AlaApiKeyClient getAlaApiKeyClient(ApiKeyClient apiKeyClient, UserDetailsClient userDetailsClient) {

        AlaApiKeyCredentialsExtractor credentialsExtractor = new AlaApiKeyCredentialsExtractor();
        credentialsExtractor.setHeaderName(apiKeyProperties.getHeader().getOverride());
        credentialsExtractor.setAlternativeHeaderNames(apiKeyProperties.getHeader().getAlternatives());

        AlaApiKeyAuthenticator authenticator = new AlaApiKeyAuthenticator();
        authenticator.setApiKeyClient(apiKeyClient);
        authenticator.setUserDetailsClient(userDetailsClient);

        return new AlaApiKeyClient(credentialsExtractor, authenticator);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("security.ip.whitelist")
    public AlaIpWhitelistClient getAlaIpWhitelistClient() {

        IpExtractor credentialsExtractor = new IpExtractor();

        AlaIpWhitelistAuthenticator authenticator = new AlaIpWhitelistAuthenticator();
        authenticator.setIpWhitelist(ipWhitelistProperties.getWhitelist());

        return new AlaIpWhitelistClient(credentialsExtractor, authenticator);
    }

    @Bean
    @ConditionalOnMissingBean
    public AlaAuthClient getAlaAuthClient(List<AlaDirectClient> authClients) {

        AlaAuthClient authClient = new AlaAuthClient();
        authClient.setAuthClients(authClients);

        return authClient;
    }

    @Bean
    @ConditionalOnProperty(prefix = "security.jwt", name = "enabled")
    public FilterRegistrationBean<Pac4jProfileManagerHttpRequestWrapperFilter> pac4jHttpRequestWrapper(Config config) {
        FilterRegistrationBean<Pac4jProfileManagerHttpRequestWrapperFilter> filterRegistrationBean = new FilterRegistrationBean<>();
        filterRegistrationBean.setFilter(new Pac4jProfileManagerHttpRequestWrapperFilter(config));
        filterRegistrationBean.setOrder(filterOrder() + 6);// This is to place this filter after the request wrapper filter in the ala-auth-plugin
        filterRegistrationBean.setInitParameters(new LinkedHashMap<String, String>());
        filterRegistrationBean.addUrlPatterns("/*");
        return filterRegistrationBean;
    }

    public static int filterOrder() {

        return 21;// FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 21
    }

}
