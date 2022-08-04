package au.org.ala.ws.security;

import org.pac4j.core.config.Config;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.FindBest;
import org.pac4j.http.client.direct.DirectBearerAuthClient;
import org.pac4j.jee.context.JEEContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Spring based Webservice Authentication Filter. This filter supports 3 modes of authentication:
 * 1) JSON Web tokens
 * 2) Legacy API keys using ALA's apikey app
 * 3) Whitelist IP
 */
// @Component
public class AlaWebServiceAuthFilterJv extends OncePerRequestFilter {

    public Logger log = LoggerFactory.getLogger(AlaWebServiceAuthFilterJv.class);

    public static final String BEARER = "Bearer";
    public static final String API_KEY = "apiKey";
    public static final String LEGACY_X_ALA_USER_ID_HEADER = "X-ALA-userId";
    public static final String USER_ID_REQUEST_PARAM = "userId";

    static final String API_KEY_HEADER_NAME = "apiKey";
//    static final List<String> LOOPBACK_ADDRESSES = [ '127.0.0.1',
//                                                     '0:0:0:0:0:0:0:1', // IP v6
//                                                     '::1' ];        // IP v6 short form

//    @Value("${spring.security.legacy.whitelist.ip:\"\"}")
//    String whitelistOfips;
//
//    @Value("${spring.security.legacy.whitelist.enabled:false}")
//    Boolean whitelistEnabled = false;
//
//    @Value("${spring.security.legacy.apikey.serviceUrl:}")
//    String legacyApiKeyServiceUrl;
//
//    @Value("${spring.security.legacy.apikey.enabled:false}")
//    Boolean legacyApiKeysEnabled = false;
//
//    @Value("${spring.security.legacy.whitelist.email:\"\"}")
//    String legacyApiKeysEmail;
//
//    @Value("${spring.security.legacy.whitelist.userid:\"\"}")
//    String legacyApiKeysUserId;
//
//    @Value("${spring.security.jwt.enabled:true}")
//    Boolean jwtApiKeysEnabled = true;
//
//    @Value("${spring.security.jwt.jwk.url}")
//    String jwkUrl;

    @Value("${security.apikey.header.override:apiKey}")
    String apiKeyHeaderName = "apiKey";

    @Value("#{'${security.apikey.ip.whitelist:}'.split(\",\")}")
    List<String> whitelistOfips = List.of();

//    @Autowired
//    ApiKeyService apiKeyService

    @Autowired
    JwtProperties jwtProperties;

    @Autowired(required = false)
    DirectBearerAuthClient bearerClient; // Could be any DirectClient?

    @Autowired(required = false)
    DirectBearerAuthClient bearerOidcClient; // Could be any DirectClient?

    @Autowired(required = false)
    Config config;

//    @Inject
//    JwtService jwtService;
//
//    @Inject
//    LegacyApiKeyService legacyApiKeyService;
//
    static final List<String> LOOPBACK_ADDRESSES = Arrays.asList(new String[]{"127.0.0.1",
            "0:0:0:0:0:0:0:1", // IP v6
            "::1"}); // IP v6 short form

    public AlaWebServiceAuthFilterJv() {}

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Optional<UserProfile> userProfile = Optional.empty();

        if (jwtProperties.isEnabled()) {
            userProfile = jwtApiKeyInterceptor(request, response);
        }

        if (!userProfile.isPresent() && jwtProperties.isFallbackToLegacyBehaviour()) {
            legacyApiKeyInterceptor(request, response);
        }

        userProfile.ifPresent(this::setAuthenticatedUserAsPrincipal);

        chain.doFilter(request, response);
/*
        if (jwtApiKeysEnabled) {
            checkForJWT(request);
        }

        // look for annotations ????
        if (legacyApiKeysEnabled){
            checkForApiKey(request);
        }

        if (whitelistEnabled){
            String clientIP = getClientIP(request);
            AuthenticatedUser authenticatedUser = checkWhitelist(clientIP);
            if (authenticatedUser != null){
                setAuthenticatedUserAsPrincipal(authenticatedUser);
            }
        }
*/
    }

    /**
     * Validate a JWT Bearer token instead of the API key.

     * @return true if the request is authorised
     */
    Optional<UserProfile> jwtApiKeyInterceptor(HttpServletRequest request, HttpServletResponse response) {

        var context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response);

        ProfileManager profileManager = new ProfileManager(context, config.getSessionStore());
        profileManager.setConfig(config);

        var accessCredentials = bearerClient.getCredentials(context, config.getSessionStore());
        if (accessCredentials.isPresent()) {

            var accessProfile = bearerClient.getUserProfile(accessCredentials.get(), context, config.getSessionStore());
            if (accessProfile.isPresent()) {

                var userProfile = accessProfile.get();

                if (jwtProperties.getRequiredScopes().containsAll(userProfile.getPermissions())) {

                    var idCredentials = bearerOidcClient.getCredentials(context, config.getSessionStore());
                    if (idCredentials.isPresent()) {

                        final var idProfile = bearerOidcClient.getUserProfile(idCredentials.get(), context, config.getSessionStore());
                        if (idProfile.isPresent()) {

                            userProfile = idProfile.get();

                            profileManager.save(
                                    bearerOidcClient.getSaveProfileInSession(context, userProfile),
                                    userProfile,
                                    bearerOidcClient.isMultiProfile(context, userProfile)
                            );
                        }
                    }

//                setAuthenticatedUserAsPrincipal(userProfile)

                    return Optional.of(userProfile);
                }

            } else {
                log.info("Bearer token present but no user info found: {}", accessCredentials);
            }
        }

        return Optional.empty();
    }

    boolean legacyApiKeyInterceptor(HttpServletRequest request, HttpServletResponse response) {

        List<String> whiteList = buildWhiteList();
        String clientIp = getClientIP(request);

        var ipOk = whiteList.contains(clientIp);

        if (!ipOk) {

            boolean keyOk = false; //apiKeyService.checkApiKey(request.getHeader(apiKeyHeaderName)).valid;

            log.debug("IP ${clientIp} ${ipOk ? 'is' : 'is not'} ok. Key ${keyOk ? 'is' : 'is not'} ok.");

            if (!keyOk) {

                log.warn(ipOk ? "No valid api key for ${controllerName}/${actionName}" : "Non-authorised IP address - ${clientIp}");
                return false;
            }

        } else {

            log.debug("IP ${clientIp} is exempt from the API Key check. Authorising.");
        }

        return true;
    }

    String getClientIP(HttpServletRequest request) {
        // External requests may be proxied by Apache, which uses X-Forwarded-For to identify the original IP.
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || LOOPBACK_ADDRESSES.contains(ip)) {
            // don't accept localhost from the X-Forwarded-For header, since it can be easily spoofed.
            ip = request.getRemoteHost();
        }
        return ip;
    }
/*
    private void checkForApiKey(HttpServletRequest request) {
        // check for requestParam - for backwards compatibilty
        String apiKeyHeader = request.getHeader(API_KEY);
        String apiKeyParam = request.getParameter(API_KEY);

        Optional<AuthenticatedUser> apiKeyUser = Optional.empty();

        if (apiKeyHeader != null){
            log.debug("Validating API key supplied in request header " + apiKeyHeader);
            apiKeyUser = legacyApiKeyService.isValidKey(apiKeyHeader);
        }
        if (apiKeyHeader == null && apiKeyParam != null){
            log.debug("Validating API key supplied in request param " + apiKeyParam);
            apiKeyUser = legacyApiKeyService.isValidKey(apiKeyParam);
        }

        if (apiKeyUser.isPresent()){

            // check X-ALA-Auth header...
            String userIdHeader = request.getHeader(LEGACY_X_ALA_USER_ID_HEADER);
            //check the body
            String userId = request.getParameter(USER_ID_REQUEST_PARAM);

            log.debug("Valid API key, userIdHeader = " + userIdHeader + ", userId param = " + userId);

            if (userIdHeader != null){
                // lookup this user
                log.debug("Checking user from header: " + userIdHeader);
                Optional<AuthenticatedUser> user = legacyApiKeyService.lookupAuthUser(userIdHeader, true);
                if (user.isPresent()){
                    log.debug("Valid user from header: " + userId);
                    setAuthenticatedUserAsPrincipal(user.get());
                } else {
                    log.debug("Invalid user from header: " + userId);
                }
            } else if (userId != null){
                // lookup this user
                log.debug("Checking user from param: " + userId);
                Optional<AuthenticatedUser> user = legacyApiKeyService.lookupAuthUser(userId, true);
                if (user.isPresent()){
                    log.debug("Valid user from param: " + userId);
                    setAuthenticatedUserAsPrincipal(user.get());
                } else {
                    log.debug("Invalid user from param: " + userId);
                }
            } else {
                log.debug("Only validated legacy api key - no user provided");
                // the user is the API key holder with a single role of
                setAuthenticatedUserAsPrincipal(apiKeyUser.get());
            }
        }
    }

    private void checkForJWT(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader != null) {
            log.info("Authorization Header detected - validating JWT");
            // parse JWT or check whitelist or Check API Key
            if (authorizationHeader.startsWith(BEARER)) {
                Optional<AuthenticatedUser> authenticatedUser = jwtService.checkJWT(authorizationHeader);
                if (authenticatedUser.isPresent()) {
                    log.info("Valid JWT supplied");
                    setAuthenticatedUserAsPrincipal(authenticatedUser.get());
                }
            }
        }
    }
*/
    private void setAuthenticatedUserAsPrincipal(UserProfile userProfile) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        List<String> credentials = new ArrayList<>();
        List<GrantedAuthority> authorities = new ArrayList<>();
        userProfile.getRoles().forEach( s -> authorities.add(new SimpleGrantedAuthority(s)));
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
                userProfile, credentials, authorities);
        token.setAuthenticated(true);
        securityContext.setAuthentication(token);
    }

    /**
     * Build white list
     * @return
     */
    List<String> buildWhiteList() {

        List<String> whiteList = new ArrayList<>();
        whiteList.addAll(LOOPBACK_ADDRESSES); // allow calls from localhost to make testing easier

        if (!whitelistOfips.isEmpty()) {
            whiteList.addAll(whitelistOfips);
        }

        return whiteList;
    }

    /**
     * Check a whitelist
     *
     * @param clientIP
     * @return
     */
//    AuthenticatedUser checkWhitelist(String clientIP){
//        if (buildWhiteList().contains(clientIP) ) {
//            AuthenticatedUser user = new AuthenticatedUser();
//            user.setUserId(legacyApiKeysUserId);
//            user.setEmail(legacyApiKeysEmail);
//            user.setRoles(Collections.singletonList(ROLE_LEGACY_APIKEY));
//            return user;
//        }
//        return null;
//    }
}