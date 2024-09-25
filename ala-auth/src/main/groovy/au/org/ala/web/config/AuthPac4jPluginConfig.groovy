package au.org.ala.web.config

import au.org.ala.pac4j.core.logout.RemoveCookieLogoutActionBuilder
import au.org.ala.pac4j.oidc.credentials.extractor.CognitoOidcExtractor
import au.org.ala.web.AffiliationSurveyFilter
import au.org.ala.web.AuthCookieProperties
import au.org.ala.web.CasClientProperties
import au.org.ala.web.CookieFilterWrapper
import au.org.ala.web.CookieMatcher
import au.org.ala.web.CooperatingFilterWrapper
import au.org.ala.web.CoreAuthProperties
import au.org.ala.web.GrailsPac4jContextProvider
import au.org.ala.web.IAuthService
import au.org.ala.web.NotBotMatcher
import au.org.ala.web.OidcClientProperties
import au.org.ala.web.OverrideSavedRequestHandler
import au.org.ala.web.Pac4jAuthService
import au.org.ala.web.Pac4jContextProvider
import au.org.ala.web.Pac4jHttpServletRequestWrapperFilter
import au.org.ala.web.Pac4jSSOStrategy
import au.org.ala.web.SSOStrategy
import au.org.ala.web.UserAgentFilterService
import au.org.ala.web.pac4j.AlaCookieCallbackLogic
import au.org.ala.web.pac4j.ConvertingFromAttributesAuthorizationGenerator
import au.org.ala.pac4j.core.CookieGenerator
import com.nimbusds.jose.util.ResourceRetriever
import grails.core.GrailsApplication
import grails.web.mapping.LinkGenerator
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.pac4j.core.authorization.generator.DefaultRolesAuthorizationGenerator
import org.pac4j.core.client.Client
import org.pac4j.core.client.Clients
import org.pac4j.core.client.direct.AnonymousClient
import org.pac4j.core.config.Config
import org.pac4j.core.context.CallContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.context.session.SessionStoreFactory
import org.pac4j.core.engine.CallbackLogic
import org.pac4j.core.engine.DefaultLogoutLogic
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.engine.LogoutLogic
import org.pac4j.core.engine.SecurityLogic
import org.pac4j.core.engine.savedrequest.SavedRequestHandler
import org.pac4j.core.http.url.DefaultUrlResolver
import org.pac4j.core.logout.handler.SessionLogoutHandler
import org.pac4j.core.matching.matcher.PathMatcher
import org.pac4j.core.util.Pac4jConstants
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.jee.context.session.JEESessionStoreFactory
import org.pac4j.jee.filter.CallbackFilter
import org.pac4j.jee.filter.LogoutFilter
import org.pac4j.jee.filter.SecurityFilter
import org.pac4j.oidc.client.OidcClient
import org.pac4j.oidc.config.OidcConfiguration
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary

import javax.servlet.DispatcherType
import java.util.regex.Pattern

import static org.pac4j.core.authorization.authorizer.IsAnonymousAuthorizer.isAnonymous
import static org.pac4j.core.authorization.authorizer.IsAuthenticatedAuthorizer.isAuthenticated
import static org.pac4j.core.authorization.authorizer.OrAuthorizer.or

@CompileStatic
@Configuration("authPac4jPluginConfiguration")
@EnableConfigurationProperties([CasClientProperties, OidcClientProperties, CoreAuthProperties, AuthCookieProperties])
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
    AuthCookieProperties authCookieProperties

    @Autowired
    LinkGenerator linkGenerator

    @Autowired
    GrailsApplication grailsApplication

    @Autowired(required = false)
    SessionLogoutHandler oidcLogoutHandler

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    IAuthService delegateService(Config config, Pac4jContextProvider pac4jContextProvider, SessionStoreFactory sessionStoreFactory, LinkGenerator grailsLinkGenerator) {
        new Pac4jAuthService(config, pac4jContextProvider, sessionStoreFactory, grailsLinkGenerator,
                oidcClientProperties.alaUseridClaim, oidcClientProperties.userNameClaim, oidcClientProperties.displayNameClaim)
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    OidcConfiguration oidcConfiguration(@Qualifier('oidcResourceRetriever') ResourceRetriever resourceRetriever) {
        OidcConfiguration config = generateBaseOidcClientConfiguration(resourceRetriever)
        return config
    }

    private OidcConfiguration generateBaseOidcClientConfiguration(ResourceRetriever resourceRetriever) {
        OidcConfiguration config = new OidcConfiguration()
        config.setClientId(oidcClientProperties.clientId)
        config.setSecret(oidcClientProperties.secret)
        config.setDiscoveryURI(oidcClientProperties.discoveryUri)
        config.setConnectTimeout(oidcClientProperties.connectTimeout)
        config.setReadTimeout(oidcClientProperties.readTimeout)
        config.setScope(oidcClientProperties.scope)
        config.setWithState(oidcClientProperties.withState)
        config.setMaxClockSkew(oidcClientProperties.maxClockSkew)
        config.customParams.putAll(oidcClientProperties.customParams)
        if (oidcClientProperties.clientAuthenticationMethod) {
            config.setClientAuthenticationMethodAsString(oidcClientProperties.clientAuthenticationMethod)
        }
        if (oidcClientProperties.allowUnsignedIdTokens) {
            config.allowUnsignedIdTokens = oidcClientProperties.allowUnsignedIdTokens
        }
//        if (logoutHandler) {
//            config.logoutHandler = logoutHandler
//        }
        if (oidcClientProperties.logoutUrl) {
            config.logoutUrl = oidcClientProperties.logoutUrl
        }

        config.resourceRetriever = resourceRetriever

        // select display mode: page, popup, touch, and wap
//        config.addCustomParam("display", "popup");
        // select prompt mode: none, consent, select_account
//        config.addCustomParam("prompt", "none");
        config
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    @Primary
    OidcClient oidcClient(OidcConfiguration oidcConfiguration, CookieGenerator authCookieGenerator) {
        def client = createOidcClientFromConfig(oidcConfiguration, authCookieGenerator)
        client.setName(DEFAULT_CLIENT)
        client.setCredentialsExtractor(new CognitoOidcExtractor(oidcConfiguration, client))
        return client
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    OidcClient oidcPromptNoneClient(CookieGenerator authCookieGenerator, @Qualifier('oidcResourceRetriever') ResourceRetriever resourceRetriever) {
        def config = generateBaseOidcClientConfiguration(resourceRetriever)
        // select prompt mode: none, consent, select_account
        config.addCustomParam("prompt", "none")
        def client = createOidcClientFromConfig(config, authCookieGenerator)
        client.setName(PROMPT_NONE_CLIENT)
        return client
    }

    private OidcClient createOidcClientFromConfig(OidcConfiguration oidcConfiguration, CookieGenerator authCookieGenerator) {
        def client = new OidcClient(oidcConfiguration)
        client.addAuthorizationGenerator(new ConvertingFromAttributesAuthorizationGenerator([coreAuthProperties.roleAttribute ?: casClientProperties.roleAttribute],coreAuthProperties.permissionAttributes, oidcClientProperties.rolePrefix, oidcClientProperties.convertRolesToUpperCase))
        client.addAuthorizationGenerator(new DefaultRolesAuthorizationGenerator(['ROLE_USER']))
        client.setUrlResolver(new DefaultUrlResolver(true))
        def logoutActionBuilder = oidcClientProperties.logoutAction.getLogoutActionBuilder(oidcConfiguration)
        if (logoutActionBuilder != null) {
            if (authCookieProperties.enabled) {
                logoutActionBuilder = new RemoveCookieLogoutActionBuilder(logoutActionBuilder, authCookieGenerator)
            }
            client.logoutActionBuilder = logoutActionBuilder
        }

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
    SessionStoreFactory sessionStoreFactory() {
        JEESessionStoreFactory.INSTANCE
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    WebContextFactory webContextFactory() {
        JEEContextFactory.INSTANCE
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @ConditionalOnMissingBean
    @Bean
    SavedRequestHandler savedRequestHandler() {
        new OverrideSavedRequestHandler()
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @ConditionalOnMissingBean
    @Bean
    SecurityLogic securityLogic(SavedRequestHandler savedRequestHandler) {
        new DefaultSecurityLogic().tap {
            it.savedRequestHandler = savedRequestHandler
        }
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    Config pac4jConfig(List<Client> clientBeans, SessionStoreFactory sessionStoreFactory, WebContextFactory webContextFactory, UserAgentFilterService userAgentFilterService, SecurityLogic securityLogic, CallbackLogic callbackLogic, @Qualifier('defaultLogoutLogic') LogoutLogic defaultLogoutLogic) {
        Clients clients = new Clients(linkGenerator.link(absolute: true, uri: CALLBACK_URI), clientBeans)

        Config config = new Config(clients)
        config.sessionStoreFactory = sessionStoreFactory
        config.webContextFactory = webContextFactory

        config.securityLogic = securityLogic
        config.logoutLogic = defaultLogoutLogic
        config.callbackLogic = callbackLogic

        if (oidcLogoutHandler) {
            config.sessionLogoutHandler = oidcLogoutHandler
        }
//        config.set
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
    @ConditionalOnMissingBean(name = 'defaultLogoutLogic')
    @Bean('defaultLogoutLogic')
    LogoutLogic defaultLogoutLogic() {
        return new DefaultLogoutLogic() {
            @Override
            protected String enhanceRedirectUrl(final CallContext ctx, final Config config, final Client client, final String redirectUrl) {
                def redirectUri = URI.create(redirectUrl)
                if (!redirectUri.isAbsolute()) {
                    return URI.create(ctx.webContext().requestURL).resolve(redirectUri).toString()
                } else {
                    return redirectUrl
                }
            }
        }
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @ConditionalOnMissingBean(name = 'authCookieGenerator')
    @Bean('authCookieGenerator')
    CookieGenerator authCookieGenerator() {
        new CookieGenerator(authCookieProperties.enabled,
                coreAuthProperties.authCookieName ?: casClientProperties.authCookieName,
                authCookieProperties.domain,
                authCookieProperties.path,
                authCookieProperties.httpOnly,
                authCookieProperties.secure,
                authCookieProperties.maxAge,
                authCookieProperties.securityPolicy,
                authCookieProperties.comment,
                authCookieProperties.quoteValue,
                authCookieProperties.encodeValue
        )
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jLogoutFilter(Config pac4jConfig) {
        final name = 'Pac4j Logout Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        // Redirect must be absolute for indirect client aka OIDC logout
        def redirectUrl = linkGenerator.link(absolute: true, uri: coreAuthProperties.defaultLogoutRedirectUri)
        def baseUrl = linkGenerator.serverBaseURL
        // Is this necessary?
        if (baseUrl.endsWith('/')) {
            baseUrl.substring(0, baseUrl.length() - 1)
        }
        LogoutFilter logoutFilter = new LogoutFilter(pac4jConfig, redirectUrl)
        if (coreAuthProperties.logoutUrlPattern) {
            logoutFilter.setLogoutUrlPattern(coreAuthProperties.logoutUrlPattern)
        } else {
            // default logout url pattern is the PAC4j url pattern with an optional base url pre-pended
            def pac4jDefaultLogoutUrlPatternValue = Pac4jConstants.DEFAULT_LOGOUT_URL_PATTERN_VALUE
            boolean startsWith = false
            boolean endsWith = false
            if (pac4jDefaultLogoutUrlPatternValue.startsWith('^')) {
                startsWith = true
                pac4jDefaultLogoutUrlPatternValue = pac4jDefaultLogoutUrlPatternValue.substring(1)
            }
            if (pac4jDefaultLogoutUrlPatternValue.endsWith('$')) {
                endsWith = true
                pac4jDefaultLogoutUrlPatternValue = pac4jDefaultLogoutUrlPatternValue.substring(0, pac4jDefaultLogoutUrlPatternValue.length() -1)
            }
            def pattern = "(${Pattern.quote(baseUrl)})?${pac4jDefaultLogoutUrlPatternValue}"
            if (startsWith) {
                pattern = '^' + pattern
            }
            if (endsWith) {
                pattern = pattern + '$'
            }
            logoutFilter.setLogoutUrlPattern(pattern.toString())
        }
        logoutFilter.setCentralLogout(coreAuthProperties.centralLogout)
        logoutFilter.setDestroySession(coreAuthProperties.destroySession)
        logoutFilter.setLocalLogout(coreAuthProperties.localLogout)
//        logoutFilter.setLogoutLogic(defaultLogoutLogic)
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
    CallbackLogic callbackLogic(CookieGenerator authCookieGenerator) {
        new AlaCookieCallbackLogic(authCookieGenerator)
    }

    @ConditionalOnProperty(prefix= 'security.oidc', name='enabled')
    @Bean
    FilterRegistrationBean pac4jCallbackFilter(Config pac4jConfig) {
        final name = 'Pac4j Callback Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        // TODO Add config property for Default URI?
        CallbackFilter callbackFilter = new CallbackFilter(pac4jConfig, linkGenerator.link(uri: '/'))
//        callbackFilter.callbackLogic = callbackLogic
        callbackFilter.defaultClient = DEFAULT_CLIENT
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
    FilterRegistrationBean pac4jProfileFilter(Config pac4jConfig, SessionStoreFactory sessionStoreFactory, WebContextFactory webContextFactory) {

        // This filter will apply to all requests but apply no SSO or authentication,
        // only wrap the request in a pac4j request wrapper if profiles exist in the session
        // Analogous to the CAS HttpServletRequestWrapperFilter
        final name = 'Pac4j Existing Profiles Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        Pac4jHttpServletRequestWrapperFilter pac4jFilter = new Pac4jHttpServletRequestWrapperFilter(pac4jConfig, sessionStoreFactory, webContextFactory)
        frb.filter = pac4jFilter
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder() + 5
        frb.urlPatterns = ['/*']
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(['security.oidc.enabled', 'security.core.affiliation-survey.enabled'])
    @Bean
    FilterRegistrationBean alaAffiliationFilter(Config pac4jConfig, SessionStoreFactory sessionStoreFactory, WebContextFactory webContextFactory) {
        final name = 'ALA Affiliation Survey Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        def scopes = coreAuthProperties.affiliationSurvey.requiredScopes
        def claim = coreAuthProperties.affiliationSurvey.affiliationClaim
        def countryClaim = coreAuthProperties.affiliationSurvey.countryClaim
        def filter = new AffiliationSurveyFilter(pac4jConfig, sessionStoreFactory, webContextFactory, scopes, claim, countryClaim)
        frb.filter = filter
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = AuthPluginConfig.filterOrder() + 6
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
