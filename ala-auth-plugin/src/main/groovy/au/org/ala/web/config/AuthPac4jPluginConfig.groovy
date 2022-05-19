package au.org.ala.web.config

import au.org.ala.web.CasClientProperties
import au.org.ala.web.CookieFilterWrapper
import au.org.ala.web.CookieMatcher
import au.org.ala.web.CooperatingFilterWrapper
import au.org.ala.web.CoreAuthProperties
import au.org.ala.web.GrailsPac4jContextProvider
import au.org.ala.web.IAuthService
import au.org.ala.web.NotBotMatcher
import au.org.ala.web.OidcClientProperties
import au.org.ala.web.Pac4jAuthService
import au.org.ala.web.Pac4jContextProvider
import au.org.ala.web.Pac4jHttpServletRequestWrapperFilter
import au.org.ala.web.Pac4jSSOStrategy
import au.org.ala.web.SSOStrategy
import au.org.ala.web.UserAgentFilterService
import grails.core.GrailsApplication
import grails.web.mapping.LinkGenerator
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.pac4j.core.authorization.generator.DefaultRolesPermissionsAuthorizationGenerator
import org.pac4j.core.authorization.generator.FromAttributesAuthorizationGenerator
import org.pac4j.core.client.Client
import org.pac4j.core.client.Clients
import org.pac4j.core.client.direct.AnonymousClient
import org.pac4j.core.config.Config
import org.pac4j.core.context.JEEContextFactory
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.JEESessionStore
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.http.url.DefaultUrlResolver
import org.pac4j.core.matching.matcher.HeaderMatcher
import org.pac4j.core.matching.matcher.PathMatcher
import org.pac4j.core.util.Pac4jConstants
import org.pac4j.jee.filter.CallbackFilter
import org.pac4j.jee.filter.LogoutFilter
import org.pac4j.jee.filter.SecurityFilter
import org.pac4j.oidc.client.OidcClient
import org.pac4j.oidc.config.OidcConfiguration
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary

import javax.servlet.DispatcherType

import static org.pac4j.core.authorization.authorizer.IsAnonymousAuthorizer.isAnonymous
import static org.pac4j.core.authorization.authorizer.IsAuthenticatedAuthorizer.isAuthenticated
import static org.pac4j.core.authorization.authorizer.OrAuthorizer.or

@CompileStatic
@Configuration("authPac4jPluginConfiguration")
@EnableConfigurationProperties([CasClientProperties, OidcClientProperties, CoreAuthProperties])
@Slf4j
class AuthPac4jPluginConfig {

    static final String DEFAULT_CLIENT = "OidcClient"
    static final String PROMPT_NONE_CLIENT = "PromptNoneClient"
    
    static final String ALLOW_ALL = "allowAll"
    static final String IS_AUTHENTICATED = "isAuthenticated"

    static final String ALA_COOKIE_MATCHER = "alaCookieMatcher"
    static final String EXCLUDE_PATHS = "excludePaths"
    public static final String CALLBACK_URI = "/callback"
    public static final String NOT_BOT_MATCHER = "notBotMatcher"

    @Autowired
    CasClientProperties casClientProperties
    @Autowired
    CoreAuthProperties coreAuthProperties
    @Autowired
    OidcClientProperties oidcClientProperties

    @Autowired
    LinkGenerator linkGenerator

    @Autowired
    GrailsApplication grailsApplication

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    IAuthService delegateService(Config config, Pac4jContextProvider pac4jContextProvider, SessionStore sessionStore, LinkGenerator grailsLinkGenerator) {
        new Pac4jAuthService(config, pac4jContextProvider, sessionStore, grailsLinkGenerator)
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    OidcConfiguration oidcConfiguration() {
        OidcConfiguration config = generateBaseOidcClientConfiguration()
        return config
    }

    private OidcConfiguration generateBaseOidcClientConfiguration() {
        OidcConfiguration config = new OidcConfiguration()
        config.setClientId(oidcClientProperties.clientId)
        config.setSecret(oidcClientProperties.secret)
        config.setDiscoveryURI(oidcClientProperties.discoveryUri)
        config.setScope(oidcClientProperties.scope)
        config.setWithState(oidcClientProperties.withState)
        config.customParams.putAll(oidcClientProperties.customParams)
        if (oidcClientProperties.clientAuthenticationMethod) {
            config.setClientAuthenticationMethodAsString(oidcClientProperties.clientAuthenticationMethod)
        }
        if (oidcClientProperties.allowUnsignedIdTokens) {
            config.allowUnsignedIdTokens = oidcClientProperties.allowUnsignedIdTokens
        }
        // select display mode: page, popup, touch, and wap
//        config.addCustomParam("display", "popup");
        // select prompt mode: none, consent, select_account
//        config.addCustomParam("prompt", "none");
        config
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    @Primary
    OidcClient oidcClient(OidcConfiguration oidcConfiguration) {
        def client = new OidcClient(oidcConfiguration)
        client.addAuthorizationGenerator(new FromAttributesAuthorizationGenerator([coreAuthProperties.roleAttribute ?: casClientProperties.roleAttribute],coreAuthProperties.permissionAttributes))
        client.addAuthorizationGenerator(new DefaultRolesPermissionsAuthorizationGenerator(['ROLE_USER'] , []))
        client.setUrlResolver(new DefaultUrlResolver(true))
        client.setName(DEFAULT_CLIENT)
        client
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    OidcClient oidcPromptNoneClient() {
        def config = generateBaseOidcClientConfiguration()
        // select prompt mode: none, consent, select_account
        config.addCustomParam("prompt", "none")
        def client = new OidcClient(config)
        client.addAuthorizationGenerator(new FromAttributesAuthorizationGenerator([coreAuthProperties.roleAttribute ?: casClientProperties.roleAttribute],coreAuthProperties.permissionAttributes))
        client.addAuthorizationGenerator(new DefaultRolesPermissionsAuthorizationGenerator(['ROLE_USER'] , []))
        client.setUrlResolver(new DefaultUrlResolver(true))
        client.setName(PROMPT_NONE_CLIENT)
        return client
    }

    @ConditionalOnProperty(prefix='security.oidc', name=['enabled', 'useAnonymousClient'])
    @Bean
    Client anonymousClient() {
        return AnonymousClient.INSTANCE
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    Pac4jContextProvider pac4jContextProvider(Config config) {
        new GrailsPac4jContextProvider(config)
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    SessionStore sessionStore() {
        JEESessionStore.INSTANCE
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    WebContextFactory webContextFactory() {
        JEEContextFactory.INSTANCE
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    Config pac4jConfig(List<Client> clientBeans, SessionStore sessionStore, WebContextFactory webContextFactory, UserAgentFilterService userAgentFilterService) {
        Clients clients = new Clients(linkGenerator.link(absolute: true, uri: CALLBACK_URI), clientBeans)

        Config config = new Config(clients)
        config.sessionStore = sessionStore
        config.webContextFactory = webContextFactory
        config.addAuthorizer(IS_AUTHENTICATED, isAuthenticated())
        config.addAuthorizer(ALLOW_ALL, or(isAuthenticated(), isAnonymous()))
        config.addMatcher(ALA_COOKIE_MATCHER, new CookieMatcher(coreAuthProperties.authCookieName ?: casClientProperties.authCookieName,".*"))
        config.addMatcher(NOT_BOT_MATCHER, new NotBotMatcher(userAgentFilterService))
        def excludeMatcher = new PathMatcher()
        (coreAuthProperties.uriExclusionFilterPattern + casClientProperties.uriExclusionFilterPattern).each {
            if (!it.startsWith("^")) {
                it = '^' + it
            }
            if (!it.endsWith('$')) {
                it += '$'
            }
            excludeMatcher.excludeRegex(it)
        }
        config.addMatcher(EXCLUDE_PATHS, excludeMatcher)
        config
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jLogoutFilter(Config pac4jConfig) {
        final name = 'Pac4j Logout Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        // Redirect must be absolute for indirect client aka OIDC logout
        def redirectUrl = linkGenerator.link(absolute: true, uri: coreAuthProperties.defaultLogoutRedirectUri)
        LogoutFilter logoutFilter = new LogoutFilter(pac4jConfig, redirectUrl)
        logoutFilter.setLogoutUrlPattern(coreAuthProperties.logoutUrlPattern)
        logoutFilter.setCentralLogout(coreAuthProperties.centralLogout)
        logoutFilter.setDestroySession(coreAuthProperties.destroySession)
        logoutFilter.setLocalLogout(coreAuthProperties.localLogout)
        frb.filter = logoutFilter
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder()
        frb.urlPatterns = [ '/logout' ]
        frb.enabled = true
        frb.asyncSupported = true
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jCallbackFilter(Config pac4jConfig) {
        final name = 'Pac4j Callback Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        // TODO Add config property for Default URI?
        CallbackFilter callbackFilter = new CallbackFilter(pac4jConfig, linkGenerator.link(uri: '/'))
        frb.filter = callbackFilter
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder()
        frb.urlPatterns = [ CALLBACK_URI ]
        frb.enabled = true
        frb.asyncSupported = true
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jUriFilter(Config pac4jConfig) {

        // This filter will apply the uriFiltersPattern
        final name = 'Pac4j Security Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        def clients = oidcClientProperties.isUseAnonymousClient()
                ? toStringParam(DEFAULT_CLIENT, AnonymousClient.class.name)
                : toStringParam(DEFAULT_CLIENT)
        SecurityFilter securityFilter = new SecurityFilter(pac4jConfig,
                clients,
                IS_AUTHENTICATED, EXCLUDE_PATHS)
        frb.filter = new CooperatingFilterWrapper(securityFilter, AuthPluginConfig.AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder() + 1
        frb.urlPatterns = coreAuthProperties.uriFilterPattern ?: casClientProperties.uriFilterPattern
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jOptionalFilter(Config pac4jConfig) {

        // This filter will apply the optional auth filter patterns - will only SSO if a cookie is present
        final name = 'Pac4j Optional Security Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        def clients = oidcClientProperties.isUseAnonymousClient()
                ? toStringParam(DEFAULT_CLIENT, AnonymousClient.class.name)
                : toStringParam(DEFAULT_CLIENT)
        SecurityFilter securityFilter = new SecurityFilter(pac4jConfig,
                clients,
                IS_AUTHENTICATED, toStringParam(ALA_COOKIE_MATCHER, EXCLUDE_PATHS))
        frb.filter = new CooperatingFilterWrapper(securityFilter, AuthPluginConfig.AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder() + 2
        frb.urlPatterns = coreAuthProperties.optionalFilterPattern +
                casClientProperties.authenticateOnlyIfCookieFilterPattern +
                casClientProperties.authenticateOnlyIfLoggedInFilterPattern +
                casClientProperties.authenticateOnlyIfLoggedInPattern
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jPromptNoneFilter(Config pac4jConfig) {

        // This filter will apply the prompt=none filter patterns
        final name = 'Pac4j Prompt None Security Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        def clients = oidcClientProperties.isUseAnonymousClient()
                ? toStringParam(PROMPT_NONE_CLIENT, AnonymousClient.class.name)
                : toStringParam(PROMPT_NONE_CLIENT)
        SecurityFilter securityFilter = new SecurityFilter(pac4jConfig,
                clients,
                ALLOW_ALL, toStringParam(NOT_BOT_MATCHER,EXCLUDE_PATHS))
        frb.filter = new CooperatingFilterWrapper(securityFilter, AuthPluginConfig.AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder() + 3
        frb.urlPatterns = casClientProperties.gatewayFilterPattern
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jPromptNoneCookieFilter(Config pac4jConfig) {

        // This filter will apply the prompt=none filter patterns if a cookie is present
        final name = 'Pac4j Prompt None Cookie Security Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        def clients = oidcClientProperties.isUseAnonymousClient()
                ? toStringParam(PROMPT_NONE_CLIENT, AnonymousClient.class.name)
                : toStringParam(PROMPT_NONE_CLIENT)
        SecurityFilter securityFilter = new SecurityFilter(pac4jConfig,
                clients,
                ALLOW_ALL, toStringParam(ALA_COOKIE_MATCHER, NOT_BOT_MATCHER, EXCLUDE_PATHS))
        frb.filter = new CooperatingFilterWrapper(new CookieFilterWrapper(securityFilter, coreAuthProperties.authCookieName), AuthPluginConfig.AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder() + 4
        frb.urlPatterns = casClientProperties.gatewayIfCookieFilterPattern
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jProfileFilter(Config pac4jConfig, SessionStore sessionStore, WebContextFactory webContextFactory) {

        // This filter will apply to all requests but apply no SSO or authentication,
        // only wrap the request in a pac4j request wrapper if profiles exist in the session
        // Analogous to the CAS HttpServletRequestWrapperFilter
        final name = 'Pac4j Existing Profiles Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        Pac4jHttpServletRequestWrapperFilter pac4jFilter = new Pac4jHttpServletRequestWrapperFilter(pac4jConfig, sessionStore, webContextFactory)
        frb.filter = pac4jFilter
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder() + 5
        frb.urlPatterns = ['/*']
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        logFilter(name, frb)
        return frb
    }

    private static void logFilter(String name, FilterRegistrationBean frb) {
        if (frb.enabled) {
            log.debug('{} enabled with type: {}', name, frb.filter)
            log.debug('{} enabled with params: {}', name, frb.initParameters)
            log.debug('{} enabled for paths: {}', name, frb.urlPatterns)
        } else {
            log.debug('{} disabled', name)
        }
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    SSOStrategy ssoStrategy(Config config) {
        new Pac4jSSOStrategy(config, null,
                oidcClientProperties.isUseAnonymousClient() ? toStringParam(AnonymousClient.class.name, DEFAULT_CLIENT) : DEFAULT_CLIENT,
                oidcClientProperties.isUseAnonymousClient() ? toStringParam(AnonymousClient.class.name, PROMPT_NONE_CLIENT) : PROMPT_NONE_CLIENT,
                IS_AUTHENTICATED, ALLOW_ALL,
                "")
    }

    private static String toStringParam(String... params) {
        params.join(Pac4jConstants.ELEMENT_SEPARATOR)
    }
}
