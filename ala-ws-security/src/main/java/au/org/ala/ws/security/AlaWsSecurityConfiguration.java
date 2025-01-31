package au.org.ala.ws.security;

import au.org.ala.userdetails.UserDetailsClient;
import au.org.ala.ws.security.authenticator.AlaApiKeyAuthenticator;
import au.org.ala.ws.security.authenticator.AlaJwtAuthenticator;
import au.org.ala.ws.security.authenticator.IpAllowListAuthenticator;
import au.org.ala.ws.security.client.AlaApiKeyClient;
import au.org.ala.ws.security.client.AlaAuthClient;
import au.org.ala.ws.security.credentials.AlaApiKeyCredentialsExtractor;
import au.org.ala.ws.security.profile.creator.AlaJwtProfileCreator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.pac4j.core.authorization.generator.FromAttributesAuthorizationGenerator;
import org.pac4j.core.client.Client;
import org.pac4j.core.client.DirectClient;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContextFactory;
import org.pac4j.core.context.session.SessionStoreFactory;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.profile.creator.ProfileCreator;
import org.pac4j.http.client.direct.DirectBearerAuthClient;
import org.pac4j.http.client.direct.IpClient;
import org.pac4j.jee.adapter.JEEFrameworkAdapter;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.session.JEESessionStoreFactory;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.List;
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

    @Bean
    @ConditionalOnMissingBean
    public SessionStoreFactory sessionStoreFactory() {
        return JEESessionStoreFactory.INSTANCE;
    }

    @Bean
    @ConditionalOnMissingBean
    public WebContextFactory webContextFactory() {
        return JEEContextFactory.INSTANCE;
    }

    @Bean
    @ConditionalOnMissingBean
    public Config pac4jConfig(List<Client> clients, WebContextFactory webContextFactory, SessionStoreFactory sessionStoreFactory) {
        Config config = new Config(clients);
        JEEFrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config);

        config.setSessionStoreFactory(sessionStoreFactory);
        config.setWebContextFactory(webContextFactory);
        return config;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security.jwt", name = "enabled")
    public OidcConfiguration oidcConfiguration(@Qualifier("oidcResourceRetriever") ResourceRetriever jwtResourceRetriever) {

        OidcConfiguration oidcConfig = new OidcConfiguration();
        oidcConfig.setDiscoveryURI(jwtProperties.getDiscoveryUri());
        oidcConfig.setClientId(jwtProperties.getClientId());
        oidcConfig.setConnectTimeout(jwtProperties.getConnectTimeoutMs());
        oidcConfig.setReadTimeout(jwtProperties.getReadTimeoutMs());
        oidcConfig.setCallUserInfoEndpoint(jwtProperties.isCallUserInfoEndpoint());

        oidcConfig.setResourceRetriever(jwtResourceRetriever);

        oidcConfig.init();

        return oidcConfig;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security.jwt", name = "enabled")
    JWKSource<SecurityContext> jwkSource(OidcConfiguration oidcConfiguration) {
        oidcConfiguration.getOpMetadataResolver();
        OIDCProviderMetadata providerMetadata = oidcConfiguration.getOpMetadataResolver().load();
        URL keySourceUrl;
        try {
            keySourceUrl = providerMetadata.getJWKSetURI().toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException("shouldn't happen", e);
        }
        return JWKSourceBuilder.create(keySourceUrl, oidcConfiguration.findResourceRetriever())
                .cache(true)
                .retrying(true)
                .refreshAheadCache(true)
                .retrying(true)
                .outageTolerant(true)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("security.jwt.enabled")
    @Qualifier("alaClient")
    public DirectBearerAuthClient alaOidcClient(OidcConfiguration oidcConfiguration, JWKSource<SecurityContext> jwkSource, CacheManager cacheManager) {


        OidcClient oidcClient = new OidcClient(oidcConfiguration);

        OIDCProviderMetadata providerMetadata = oidcConfiguration.getOpMetadataResolver().load();

        ProfileCreator profileCreator;
        if (jwtProperties.isUseAlaCustomProfileCreator()) {
            var alaProfileCreator = new AlaJwtProfileCreator(oidcConfiguration, oidcClient);

//            alaProfileCreator.setAuthorizationGenerator(new FromAttributesAuthorizationGenerator(jwtProperties.getRoleClaims()));
            alaProfileCreator.setUserIdClaim(jwtProperties.getUserIdClaim());

            alaProfileCreator.setRolesFromAccessToken(jwtProperties.isRolesFromAccessToken());
            if (alaProfileCreator.isRolesFromAccessToken()) {
                alaProfileCreator.setAccessTokenRoleClaims(jwtProperties.getRoleClaims());
            }

            alaProfileCreator.setRolePrefix(jwtProperties.getRolePrefix());
            alaProfileCreator.setRoleToUppercase(jwtProperties.isRoleToUppercase());

            alaProfileCreator.setCacheManager(cacheManager);

            profileCreator = alaProfileCreator;
        } else {
            profileCreator = new OidcProfileCreator(oidcConfiguration, oidcClient);
        }

        Authenticator authenticator;
        if (jwtProperties.isUseAlaCustomJwtAuthenticator()) {
            var alaJwtAuthenticator = new AlaJwtAuthenticator();
            alaJwtAuthenticator.setIssuer(providerMetadata.getIssuer());
            alaJwtAuthenticator.setExpectedJWSAlgs(Set.copyOf(providerMetadata.getIDTokenJWSAlgs()));
            alaJwtAuthenticator.setKeySource(jwkSource);
            alaJwtAuthenticator.setAcceptedAudiences(jwtProperties.getAcceptedAudiences());
            alaJwtAuthenticator.setRequiredClaims(jwtProperties.getRequiredClaims());
            alaJwtAuthenticator.setProhibitedClaims(jwtProperties.getProhibitedClaims());
            alaJwtAuthenticator.setRequiredScopes(jwtProperties.getRequiredScopes());


            authenticator = alaJwtAuthenticator;
        } else {
            authenticator = new JwtAuthenticator(jwtProperties.getSignatureConfigurations().stream().map(SignatureConfigurationProperties::toSignatureConfiguration).toList());
        }

        DirectBearerAuthClient client = new DirectBearerAuthClient(authenticator, profileCreator);
        client.setAuthorizationGenerator(new FromAttributesAuthorizationGenerator(jwtProperties.getRoleClaims()));

//        client.set

        return client;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "security.apikey", name = "enabled")
    @Qualifier("alaClient")
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
    @Qualifier("alaClient")
    public IpClient getAlaIpWhitelistClient() {

        return new IpClient(new IpAllowListAuthenticator(ipWhitelistProperties.getWhitelist()));
    }

    @Bean
    @ConditionalOnMissingBean
    public AlaAuthClient getAlaAuthClient(@Qualifier("alaClient") List<DirectClient> authClients) {

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
