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
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.squareup.moshi.Moshi;
import com.squareup.moshi.adapters.Rfc3339DateJsonAdapter;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import org.pac4j.core.authorization.generator.FromAttributesAuthorizationGenerator;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContextFactory;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.http.credentials.extractor.IpExtractor;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.session.JEESessionStore;
import org.pac4j.oidc.config.OidcConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import retrofit2.Retrofit;
import retrofit2.converter.moshi.MoshiConverterFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

@Configuration
@EnableConfigurationProperties({JwtProperties.class, ApiKeyProperties.class, IpWhitelistProperties.class, UserDetailsProperties.class})
public class AlaWsSecurityConfiguration {
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
    @ConditionalOnProperty(prefix = "security.jwt", name = "enabled")
    public OidcConfiguration oidcConfiguration() {

        OidcConfiguration oidcConfig = new OidcConfiguration();
        oidcConfig.setDiscoveryURI(jwtProperties.getDiscoveryUri());
        oidcConfig.setClientId(jwtProperties.getClientId());
        oidcConfig.setConnectTimeout(jwtProperties.getConnectTimeoutMs());
        oidcConfig.setReadTimeout(jwtProperties.getReadTimeoutMs());

        return oidcConfig;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("security.jwt.enabled")
    public AlaOidcClient getAlaOidcClient(OidcConfiguration oidcConfiguration) {

        AlaOidcCredentialsExtractor credentialsExtractor = new AlaOidcCredentialsExtractor();

        AlaOidcAuthenticator authenticator = new AlaOidcAuthenticator(oidcConfiguration);
        OIDCProviderMetadata providerMetadata = oidcConfiguration.findProviderMetadata();
        authenticator.setIssuer(providerMetadata.getIssuer());
        authenticator.setExpectedJWSAlgs(Set.copyOf(providerMetadata.getIDTokenJWSAlgs()));
        URL keySourceUrl;
        try {
            keySourceUrl = providerMetadata.getJWKSetURI().toURL();
        } catch (MalformedURLException e) {
            throw new RuntimeException("shouldn't happen", e);
        }
        authenticator.setKeySource(new RemoteJWKSet<>(keySourceUrl, oidcConfiguration.findResourceRetriever()));
        authenticator.setAuthorizationGenerator(new FromAttributesAuthorizationGenerator(jwtProperties.getRoleAttributes(), jwtProperties.getPermissionAttributes()));

        authenticator.setRequiredClaims(jwtProperties.getRequiredClaims());
        authenticator.setRequiredScopes(jwtProperties.getRequiredScopes());

        authenticator.setRolesFromAccessToken(jwtProperties.isRolesFromAccessToken());
        if (authenticator.isRolesFromAccessToken()) {
            authenticator.setAccessTokenRoleClaims(jwtProperties.getRoleAttributes());
        }

        authenticator.setRolePrefix(jwtProperties.getRolePrefix());
        authenticator.setRoleToUppercase(jwtProperties.isRoleToUppercase());

        return new AlaOidcClient(credentialsExtractor, authenticator);
    }

    @Bean
    @ConditionalOnMissingBean
    public OkHttpClient okHttpClient() {
        OkHttpClient.Builder httpClient = new OkHttpClient.Builder();
        return httpClient.build();
    }

    @Bean
    @ConditionalOnMissingBean
    public Moshi moshi() {
        return new Moshi.Builder().add(Date.class, new Rfc3339DateJsonAdapter().nullSafe()).build();
    }

    @Bean
    @ConditionalOnMissingBean
    public UserDetailsClient userDetailsClient(OkHttpClient okHttpClient, Moshi moshi) {
        return new UserDetailsClient.Builder((Call.Factory) okHttpClient, userDetailsProperties.getUrl()).moshi(moshi).build();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty("security.apikey.enabled")
    public AlaApiKeyClient getAlaApiKeyClient(OkHttpClient okHttpClient, Moshi moshi) {

        AlaApiKeyCredentialsExtractor credentialsExtractor = new AlaApiKeyCredentialsExtractor();
        credentialsExtractor.setHeaderName(apiKeyProperties.getHeader().getOverride());
        credentialsExtractor.setAlternativeHeaderNames(apiKeyProperties.getHeader().getAlternatives());

        ApiKeyClient apiKeyClient = new Retrofit.Builder().baseUrl(apiKeyProperties.getAuth().getServiceUrl()).addConverterFactory(MoshiConverterFactory.create(moshi)).client(okHttpClient).build().create(ApiKeyClient.class);

        AlaApiKeyAuthenticator authenticator = new AlaApiKeyAuthenticator();
        authenticator.setApiKeyClient(apiKeyClient);

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
    public FilterRegistrationBean pac4jHttpRequestWrapper(Config config) {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(new Pac4jProfileManagerHttpRequestWrapperFilter(config));
        filterRegistrationBean.setOrder(filterOrder() + 6);// This is to place this filter after the request wrapper filter in the ala-auth-plugin
        filterRegistrationBean.setInitParameters(new LinkedHashMap<String, String>());
        filterRegistrationBean.addUrlPatterns("/*");
        return filterRegistrationBean;
    }

    public static int filterOrder() {

        return 21;// FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 21
    }

    public static String getJWT_CLIENT() {
        return JWT_CLIENT;
    }

    public JwtProperties getJwtProperties() {
        return jwtProperties;
    }

    public void setJwtProperties(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public ApiKeyProperties getApiKeyProperties() {
        return apiKeyProperties;
    }

    public void setApiKeyProperties(ApiKeyProperties apiKeyProperties) {
        this.apiKeyProperties = apiKeyProperties;
    }

    public IpWhitelistProperties getIpWhitelistProperties() {
        return ipWhitelistProperties;
    }

    public void setIpWhitelistProperties(IpWhitelistProperties ipWhitelistProperties) {
        this.ipWhitelistProperties = ipWhitelistProperties;
    }

    public UserDetailsProperties getUserDetailsProperties() {
        return userDetailsProperties;
    }

    public void setUserDetailsProperties(UserDetailsProperties userDetailsProperties) {
        this.userDetailsProperties = userDetailsProperties;
    }

    private static final String JWT_CLIENT = "JwtClient";
    @Autowired
    private JwtProperties jwtProperties;
    @Autowired
    private ApiKeyProperties apiKeyProperties;
    @Autowired
    private IpWhitelistProperties ipWhitelistProperties;
    @Autowired
    private UserDetailsProperties userDetailsProperties;
}
