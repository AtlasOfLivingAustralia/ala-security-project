package au.ala.org.ws.security

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.exceptions.SignatureVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import grails.converters.JSON
import groovy.util.logging.Slf4j;
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.DependsOn
import org.springframework.http.HttpHeaders
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

import javax.annotation.PostConstruct
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.security.interfaces.RSAPublicKey

/**
 * Spring based Webservice Authentication Filter. This filter supports 3 modes of authentication:
 * 1) JSON Web tokens
 * 2) Legacy API keys using ALA's apikey app
 * 3) Whitelist IP
 */
@Component
@DependsOn("springSecurityFilterChain")
@Slf4j
class AlaWebServiceAuthFilter extends OncePerRequestFilter {

    public static final String BEARER = "Bearer"
    @Autowired
    @Qualifier("springSecurityFilterChain")
    private Filter springSecurityFilterChain;

    @Value('${spring.security.legacy.whitelist.ip:""}')
    String whitelistOfips;

    @Value('${spring.security.legacy.whitelist.enabled:false}')
    Boolean whitelistEnabled

    @Value('${spring.security.legacy.apikey.serviceUrl}')
    String legacyApiKeyServiceUrl

    @Value('${spring.security.legacy.apikey.enabled:false}')
    Boolean legacyApiKeysEnabled

    @Value('${spring.security.legacy.whitelist.email:""}')
    String legacyApiKeysEmail

    @Value('${spring.security.legacy.whitelist.userid:""}')
    String legacyApiKeysUserId

    @Value('${spring.security.legacy.roles:""}')
    String legacyApiKeysRoles

    @Value('${spring.security.jwt.enabled:true}')
    Boolean jwtApiKeysEnabled

    @Value('${spring.security.jwt.jwk.url}')
    String jwkUrl

    static final List LEGACY_API_KEY_HEADER_NAMES = [
            "apiKey",
            "api_key",
            "Authorization"
    ]

    static final List<String> LOOPBACK_ADDRESSES = ["127.0.0.1",
                                                    "0:0:0:0:0:0:0:1", // IP v6
                                                    "::1"] // IP v6 short form

    /** The name of the filter which this filter should be placed after in the spring security filter array. */
    String addAfterFilterName = "LogoutFilter"

    /** The idx at which this filter should be placed after in the spring security filter array. */
    int addAfterFilterIdx = 4

    def serviceMethod() {}

    public AlaWebServiceAuthFilter(){}

    @PostConstruct
    void init(){
        def filterChains = springSecurityFilterChain.filterChains[0]

        // get index of configured "addAfterFilterName"
        int filterIdx = -1
        filterChains.filters.eachWithIndex { filter, idx ->
           if (filter.getClass().getSimpleName() == addAfterFilterName || filter.getClass().getCanonicalName() == addAfterFilterName){
               filterIdx = idx
           }
        }
        if (filterIdx > 0){
            filterChains.filters.add(filterIdx + 1, this)
        } else {
            filterChains.filters.add(addAfterFilterIdx, this)
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (jwtApiKeysEnabled) {
            String authorizationHeader = ((HttpServletRequest) request).getHeader(HttpHeaders.AUTHORIZATION)
            if (authorizationHeader != null) {
                // parse JWT or check whitelist or Check API Key
                if (authorizationHeader.startsWith(BEARER)) {
                    AuthenticatedUser authenticatedUser = checkJWT(authorizationHeader)
                    if (authenticatedUser) {
                        setAuthenticatedUserAsPrincipal(authenticatedUser)
                    }
                }
            }
        }

        if (legacyApiKeysEnabled){
            String apiKeyHeader = getLegacyApiKeyHeader((HttpServletRequest) request)
            if (apiKeyHeader) {
                AuthenticatedUser authenticatedUser = checkLegacyApiKey(apiKeyHeader)
                if (authenticatedUser) {
                    setAuthenticatedUserAsPrincipal(authenticatedUser)
                }
            }
        }

        if (whitelistEnabled){
            String clientIP = getClientIP(request)
            AuthenticatedUser authenticatedUser = checkWhitelist(clientIP)
            if (authenticatedUser){
                setAuthenticatedUserAsPrincipal(authenticatedUser)
            }
        }

        chain.doFilter(request, response);
    }

    private String getLegacyApiKeyHeader(HttpServletRequest request){
        String apiKeyHeader = null
        LEGACY_API_KEY_HEADER_NAMES.each {
            String hdr = request.getHeader(it)
            if (hdr){
                apiKeyHeader = hdr
            }
        }
        apiKeyHeader
    }

    private void setAuthenticatedUserAsPrincipal(AuthenticatedUser authenticatedUser) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        List<String> credentials = new ArrayList<>()
        List<GrantedAuthority> authorities = new ArrayList<>()
        authenticatedUser.roles.each { authorities.add(new SimpleGrantedAuthority(it)) }
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(
                authenticatedUser, credentials, authorities)
        token.setAuthenticated(true)
        securityContext.setAuthentication(token)
    }


    /**
     * If successful, returns an AuthenticatedUser
     * @param ke    y
     * @return
     */
    AuthenticatedUser checkLegacyApiKey(String key) {
        Map response
        try {
            def conn = new URL("${legacyApiKeyServiceUrl}${key}").openConnection()
            if (conn.responseCode == HttpServletResponse.SC_OK) {
                response = JSON.parse(conn.content.text as String)
                if (response.valid) {
                    return new AuthenticatedUser(
                        email: response.userEmail,
                        userId: response.userId,
                        roles: legacyApiKeysRoles ? legacyApiKeysRoles.split(",").collect { it.trim() } : [],
                        attributes: [:]
                    )
                }
            } else {
                log.info "Rejected - " + (key ? "using key ${key}" : "no key present")
                null
            }
        } catch (Exception e) {
            log.error "Failed to lookup key ${key}", e
            null
        }
        null
    }

    /**
     * Creates a user to emulate a proper user with the new JWT based authentication.
     * @return
     */
    private AuthenticatedUser createLegacyAuthenticatedUser() {
        new AuthenticatedUser(
                email: legacyApiKeysEmail,
                userId: legacyApiKeysUserId,
                roles: legacyApiKeysRoles ? legacyApiKeysRoles.split(",").collect { it.trim() } : [],
                attributes: [:]
        )
    }

    /**
     * Check a whitelist
     *
     * @param clientIP
     * @return
     */
    AuthenticatedUser checkWhitelist(String clientIP){
        if (buildWhiteList().contains(clientIP) ) {
            return new AuthenticatedUser(
                    email: legacyApiKeysEmail,
                    userId: legacyApiKeysUserId,
                    roles: legacyApiKeysRoles ? legacyApiKeysRoles.split(",").collect { it.trim() } : [],
                    attributes: [:]
            )
        }
        null
    }

    /**
     * Verifies the signature of a JWT and retrieves the user information.
     *
     * @param authorizationHeader
     * @return
     */
    AuthenticatedUser checkJWT(String authorizationHeader) {

        try {
            // https://auth0.com/docs/security/tokens/json-web-tokens/validate-json-web-tokens
            String token = authorizationHeader.substring(7)

            // decode and verify
            DecodedJWT jwt = JWT.decode(token);
            JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
            String keyId = jwt.getKeyId();
            Jwk jwk = provider.get(keyId);
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

            try {
                algorithm.verify(jwt);
                // check the expiry....
                if (jwt.getExpiresAt().before(new Date())){
                    return null
                }
                List roles = jwt.getClaims().get("role").asList(String.class)
                String email = jwt.getClaims().get("email")
                String userId = jwt.getClaims().get("userid")
                new AuthenticatedUser(email: email, userId: userId, roles: roles, attributes: jwt.getClaims())
            } catch (SignatureVerificationException e) {
                log.error("Verify of JWT failed")
                null
            }
        } catch (JWTDecodeException e){
            // this will happen for some legacy API keys which are past in the Authorization header
            log.debug("Decode of JWT failed, supplied authorizationHeader is not a recognised JWT")
            log.debug(e.getMessage(), e)
        }
    }

    /**
     * Build white list
     * @return
     */
    List<String> buildWhiteList() {
        List<String> whiteList = []
        whiteList.addAll(LOOPBACK_ADDRESSES) // allow calls from localhost to make testing easier
        if (whitelistOfips) {
            whiteList.addAll(whitelistOfips.split(',').collect { it.trim() })
        }
        whiteList
    }

    String getClientIP(HttpServletRequest request) {
        // External requests may be proxied by Apache, which uses X-Forwarded-For to identify the original IP.
        String ip = request.getHeader("X-Forwarded-For")
        if (!ip || LOOPBACK_ADDRESSES.contains(ip)) {
            // don't accept localhost from the X-Forwarded-For header, since it can be easily spoofed.
            ip = request.getRemoteHost()
        }
        ip
    }
}