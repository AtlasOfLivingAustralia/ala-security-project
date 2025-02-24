package au.org.ala.ws.security.profile.creator;

import au.org.ala.ws.security.credentials.JwtCredentials;
import au.org.ala.ws.security.profile.AlaM2MUserProfile;
import au.org.ala.ws.security.profile.AlaOidcUserProfile;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.Request;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.profile.jwt.JwtClaims;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.exceptions.OidcException;
import org.pac4j.oidc.exceptions.UserInfoErrorResponseException;
import org.pac4j.oidc.profile.OidcProfile;
import org.pac4j.oidc.profile.OidcProfileDefinition;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.pac4j.core.profile.AttributeLocation.PROFILE_ATTRIBUTE;
import static org.pac4j.core.util.CommonHelper.assertNotNull;

/** Port parts of the old AlaOidcAuthenticator to the new pac4j 6.0.0 API */
// TODO this class shouldn't extend OidcProfileCreator because it doesn't handle front end authentication, but rather
//  backend authentication only.
public class AlaJwtProfileCreator extends OidcProfileCreator {

    public static final Logger log = LoggerFactory.getLogger(AlaJwtProfileCreator.class);

    public static final String PARSED_JWT_ATTRIBUTE = "ala.parsed.jwt";

    private CacheManager cacheManager;
    private Cache cache;

    private Set<String> acceptedAudience = Collections.emptySet();
    private Issuer issuer;
    private Set<JWSAlgorithm> expectedJWSAlgs;
    private JWKSource<SecurityContext> keySource;
    private String userIdClaim;
    private List<String> requiredClaims;
    private List<String> prohibitedClaims = Collections.emptyList();
    private List<String> requiredScopes;
    private List<String> accessTokenRoleClaims;
    private boolean rolesFromAccessToken = false;
    private String rolePrefix = "";
    private boolean roleToUppercase = true;

    public AlaJwtProfileCreator(final OidcConfiguration configuration, final OidcClient client) {
        super(configuration, client);
    }

    @Override
    protected void internalInit(boolean forceReinit) {
        assertNotNull("configuration", configuration);

        setProfileDefinitionIfUndefined(new OidcProfileDefinition((params) -> new AlaOidcUserProfile(params[0].toString())));

        if (cacheManager != null) {
            cache = cacheManager.getCache("user-profile");
        }

        if (cache == null) {
            log.warn("No 'user-profile' caching configured.");
        }

        super.internalInit(forceReinit);
    }

    @Override
    @SuppressWarnings("unchecked")
    public Optional<UserProfile> create(final CallContext ctx, final Credentials credentials) {
        init();

        OidcCredentials oidcCredentials = null;
        AccessToken accessToken = null;

        String token = ((TokenCredentials) credentials).getToken();
//        accessToken = new BearerAccessToken(token);
        boolean jwtFlow = credentials instanceof JwtCredentials;
        JWT jwtToken;
        if (jwtFlow) {
            jwtToken = ((JwtCredentials) credentials).getJwtAccessToken();
            // TODO do I need to validate JWT here?
        } else {
            jwtToken = null;
        }


        String userId;

        String jwtId = null;
        String subject = null;
        List<String> audience = null;
        String issuer;

        try {

            final Nonce nonce;
            if (configuration.isUseNonce()) {
                nonce = new Nonce((String) ctx.sessionStore().get(ctx.webContext(), client.getNonceSessionAttributeName()).orElse(null));
            } else {
                nonce = null;
            }

            // attempt to get scopes from jwt access token first
            List<String> accessTokenScopeList = null;
            if (jwtToken != null) {
                var claims = jwtToken.getJWTClaimsSet();
                if (claims != null) {
                    var scopeClaim = claims.getClaim("scope");
                    if (scopeClaim instanceof List) {
                        accessTokenScopeList = (List<String>) scopeClaim;
                    } else if (scopeClaim instanceof String) {
                        accessTokenScopeList = Arrays.stream(((String) scopeClaim).split(Pattern.quote(" "))).filter(s -> !s.isEmpty()).collect(Collectors.toList());
                    } else {
                        log.debug("Couldn't parse scope claim value: {}", scopeClaim);
                    }
                }
            }

            // if we don't have a jwt or we don't have the scopes from the jwt access token, call the introspection endpoint
            TokenIntrospectionSuccessResponse tokenResponse;
            if (!jwtFlow || accessTokenScopeList == null) {
                tokenResponse = callTokenIntrospectionEndpoint(token);
            } else {
                tokenResponse = null;
            }

            if (accessTokenScopeList == null) {
                accessTokenScopeList = tokenResponse.getScope().toStringList();
            }
            Set<String> accessTokenScopeSet = accessTokenScopeList != null ? new LinkedHashSet<>(accessTokenScopeList) : Collections.emptySet();

            accessToken = new BearerAccessToken(
                    token,
                    (jwtToken != null ? jwtToken.getJWTClaimsSet().getExpirationTime() : tokenResponse.getExpirationTime()).getTime(),
                    Scope.parse(accessTokenScopeSet)
            );

            userId = jwtToken != null ? jwtToken.getJWTClaimsSet().getStringClaim(userIdClaim) : tokenResponse.getStringParameter(userIdClaim);

            subject = jwtToken != null ? jwtToken.getJWTClaimsSet().getSubject() : tokenResponse.getSubject().getValue();
            audience = jwtToken != null ? jwtToken.getJWTClaimsSet().getAudience() : tokenResponse.getAudience().stream().map(Identifier::getValue).toList();
            issuer = jwtToken != null ? jwtToken.getJWTClaimsSet().getIssuer() : tokenResponse.getIssuer().getValue();
            jwtId = jwtToken != null ? jwtToken.getJWTClaimsSet().getJWTID() : tokenResponse.getJWTID().getValue();

            var accessTokenRoles = jwtToken != null ? getRoles(jwtToken.getJWTClaimsSet()) : getRoles(tokenResponse);

            AlaOidcUserProfile alaOidcUserProfile = null;

            boolean hasOpenIdScope = accessTokenScopeSet.contains(OIDCScopeValue.OPENID.getValue());
            boolean hasProfileScope = accessTokenScopeSet.contains(OIDCScopeValue.PROFILE.getValue());

            if (hasProfileScope) {
                if (cache != null) {
                    Cache.ValueWrapper cachedProfile = cache.get(accessToken);
                    if (cachedProfile != null) {
                        alaOidcUserProfile = (AlaOidcUserProfile) cachedProfile.get();
                    }
                }

                if (alaOidcUserProfile == null) {

                    alaOidcUserProfile = new AlaOidcUserProfile(userId);
                }

            } else if (userId != null && !userId.isEmpty()) {
                alaOidcUserProfile = new AlaOidcUserProfile(userId);
            } else {
                alaOidcUserProfile = new AlaM2MUserProfile(subject, issuer, audience);
                alaOidcUserProfile.addRoles(accessTokenScopeSet);
//                alaOidcUserProfile.addPermissions(accessTokenScopeSet);
            }

            if (hasOpenIdScope && configuration.isCallUserInfoEndpoint()) {
                final var uri = configuration.getOpMetadataResolver().load().getUserInfoEndpointURI();
                try {
                    callUserInfoEndpoint(uri, accessToken, alaOidcUserProfile);
                } catch (final UserInfoErrorResponseException e) {
                    // bearer call -> no profile returned
//                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Error calling user info endpoint", e);
                    } else {
                        log.warn("Error calling user info endpoint: {}", e.getMessage());
                    }
                }
            }


            // add attributes from the jwt token to the profile
            if (jwtFlow && configuration.isIncludeAccessTokenClaimsInProfile()) {
                collectClaimsFromJwtAccessTokenIfAny((JwtCredentials) credentials, nonce, alaOidcUserProfile);
            }
            // TODO this is always false because oidcCredentials is always null
            if (oidcCredentials != null && configuration.isIncludeAccessTokenClaimsInProfile()) {
                collectClaimsFromAccessTokenIfAny(oidcCredentials, nonce, alaOidcUserProfile);
            }

            // session expiration with token behavior
//            profile.setTokenExpirationAdvance(configuration.getTokenExpirationAdvance());

            if (alaOidcUserProfile != null) {
                alaOidcUserProfile.setAccessToken(accessToken);
                if (accessTokenRoles != null && !accessTokenRoles.isEmpty()) {
                    alaOidcUserProfile.addRoles(accessTokenRoles);
                }
//                alaOidcUserProfile.addPermissions(accessTokenScopeSet);
                credentials.setUserProfile(alaOidcUserProfile);
            }

            return Optional.of(alaOidcUserProfile);
        } catch (final IOException | ParseException |
                       com.nimbusds.oauth2.sdk.ParseException | TokenIntrospectResponseException e) {
            throw new OidcException(e);
        }
    }

    private void collectClaimsFromJwtAccessTokenIfAny(final JwtCredentials credentials,
                                                      final Nonce nonce, UserProfile profile) {
        try {
            var accessTokenJwt = credentials.getJwtAccessToken();
            var accessTokenClaims = configuration.getOpMetadataResolver().getTokenValidator().validate(accessTokenJwt, nonce);

            // add attributes of the access token if they don't already exist
            addClaimsToProfile(profile, accessTokenClaims);
        } catch (final JOSEException | BadJOSEException e) {
            log.debug(e.getMessage(), e);
        } catch (final Exception e) {
            throw new OidcException(e);
        }
    }

    private void addClaimsToProfile(UserProfile profile, IDTokenClaimsSet accessTokenClaims) throws com.nimbusds.oauth2.sdk.ParseException {
        for (var entry : accessTokenClaims.toJWTClaimsSet().getClaims().entrySet()) {
            var key = entry.getKey();
            var value = entry.getValue();
            if (!JwtClaims.SUBJECT.equals(key) && profile.getAttribute(key) == null) {
                getProfileDefinition().convertAndAdd(profile, PROFILE_ATTRIBUTE, key, value);
            }
        }
    }

    private void collectClaimsFromAccessTokenIfAny(final OidcCredentials credentials,
                                                   final Nonce nonce, UserProfile profile) {
        try {
            var accessToken = credentials.toAccessToken();
            if (accessToken != null) {
                var accessTokenJwt = JWTParser.parse(accessToken.getValue());
                var accessTokenClaims = configuration.getOpMetadataResolver().getTokenValidator().validate(accessTokenJwt, nonce);

                // add attributes of the access token if they don't already exist
                addClaimsToProfile(profile, accessTokenClaims);
            }
        } catch (final ParseException | JOSEException | BadJOSEException e) {
            log.debug(e.getMessage(), e);
        } catch (final Exception e) {
            throw new OidcException(e);
        }
    }

    private Collection<String> getRoles(TokenIntrospectionSuccessResponse response) {
        if (!rolesFromAccessToken) {
            return List.of();
        }

        // this probably has to be the userinfo endpoint instead of the token introspection endpoint
        Stream<String> roles = accessTokenRoleClaims.stream()
                .map(response::getStringListParameter)
                .filter(Objects::nonNull)
                .flatMap(Collection::stream);

        return getRoles(roles);
    }

    private Collection<String> getRoles(JWTClaimsSet claimsSet) {
        if (!rolesFromAccessToken) {
            return List.of();
        }

        Stream<String> roles = accessTokenRoleClaims.stream()
                .map(claimsSet::getClaim)
                .filter(Objects::nonNull)
                .flatMap((Object roleClaim) -> {
                    Stream<String> result;
                    if (roleClaim instanceof String) {
                        result = Stream.of(((String) roleClaim).split(Pattern.quote(",")));
                    } else if (roleClaim.getClass().isArray() && roleClaim.getClass().getComponentType().isAssignableFrom(String.class)) {
                        result = Stream.of((String[]) roleClaim);
                    } else if (Collection.class.isAssignableFrom(roleClaim.getClass())) {
                        result = ((Collection<String>) roleClaim).stream();
                    } else {
                        log.debug("Couldn't parse role claim value: {}", roleClaim);
                        result = Stream.empty();
                    }
                    return result;
                });

        return getRoles(roles);
    }

    private Collection<String> getRoles(Stream<String> roles) {
        if (this.rolePrefix != null && !this.rolePrefix.trim().isEmpty()) {
            roles = roles.map(role -> role.startsWith(this.rolePrefix) ? role : this.rolePrefix + role);
        }

        if (this.roleToUppercase) {
            roles = roles.map(String::toUpperCase);
        }

        return roles.collect(Collectors.toSet());
    }

    public TokenIntrospectionSuccessResponse callTokenIntrospectionEndpoint(final String token) throws IOException, com.nimbusds.oauth2.sdk.ParseException, TokenIntrospectResponseException {
        OIDCProviderMetadata opMetadata = this.configuration.getOpMetadataResolver().load();
        if (opMetadata.getUserInfoEndpointURI() != null && token != null) {
            Request userInfoRequest = new TokenIntrospectionRequest(opMetadata.getTokenEndpointURI(), new BearerAccessToken(token));
            HTTPRequest userInfoHttpRequest = userInfoRequest.toHTTPRequest();
            this.configuration.configureHttpRequest(userInfoHttpRequest);
            HTTPResponse httpResponse = userInfoHttpRequest.send();
            log.debug("Token introspect response: status={}, content={}", httpResponse.getStatusCode(), httpResponse.getContent());
            TokenIntrospectionResponse tokenIntrospectionResponse = TokenIntrospectionResponse.parse(httpResponse);
            if (tokenIntrospectionResponse instanceof TokenIntrospectionErrorResponse) {
                ErrorObject error = ((TokenIntrospectionErrorResponse)tokenIntrospectionResponse).getErrorObject();
                log.error("Bad User Info response, error={}", error);
                throw new TokenIntrospectResponseException(error.toString());
            }

            return (TokenIntrospectionSuccessResponse)tokenIntrospectionResponse;
        }
        return null;
    }

    public AlaOidcUserProfile generateAlaUserProfile(String userId, UserProfile profile) {
        AlaOidcUserProfile alaOidcUserProfile = new AlaOidcUserProfile(userId);
        alaOidcUserProfile.addAttributes(profile.getAttributes());
        alaOidcUserProfile.setRoles(profile.getRoles());
//        alaOidcUserProfile.setPermissions(profile.getPermissions());
//        alaOidcUserProfile.addPermissions(accessTokenScopeSet);
        return alaOidcUserProfile;
    }

    // Getters and setters for the custom fields

    public CacheManager getCacheManager() {
        return cacheManager;
    }

    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public Set<String> getAcceptedAudience() {
        return acceptedAudience;
    }

    public void setAcceptedAudience(Set<String> acceptedAudience) {
        this.acceptedAudience = acceptedAudience;
    }

    public Issuer getIssuer() {
        return issuer;
    }

    public void setIssuer(Issuer issuer) {
        this.issuer = issuer;
    }

    public Set<JWSAlgorithm> getExpectedJWSAlgs() {
        return expectedJWSAlgs;
    }

    public void setExpectedJWSAlgs(Set<JWSAlgorithm> expectedJWSAlgs) {
        this.expectedJWSAlgs = expectedJWSAlgs;
    }

    public JWKSource<SecurityContext> getKeySource() {
        return keySource;
    }

    public void setKeySource(JWKSource<SecurityContext> keySource) {
        this.keySource = keySource;
    }

    public String getUserIdClaim() {
        return userIdClaim;
    }

    public void setUserIdClaim(String userIdClaim) {
        this.userIdClaim = userIdClaim;
    }

    public List<String> getRequiredClaims() {
        return requiredClaims;
    }

    public void setRequiredClaims(List<String> requiredClaims) {
        this.requiredClaims = requiredClaims;
    }

    public List<String> getProhibitedClaims() {
        return prohibitedClaims;
    }

    public void setProhibitedClaims(List<String> prohibitedClaims) {
        this.prohibitedClaims = prohibitedClaims;
    }

    public List<String> getRequiredScopes() {
        return requiredScopes;
    }

    public void setRequiredScopes(List<String> requiredScopes) {
        this.requiredScopes = requiredScopes;
    }

    public List<String> getAccessTokenRoleClaims() {
        return accessTokenRoleClaims;
    }

    public void setAccessTokenRoleClaims(List<String> accessTokenRoleClaims) {
        this.accessTokenRoleClaims = accessTokenRoleClaims;
    }

    public boolean isRolesFromAccessToken() {
        return rolesFromAccessToken;
    }

    public void setRolesFromAccessToken(boolean rolesFromAccessToken) {
        this.rolesFromAccessToken = rolesFromAccessToken;
    }

    public String getRolePrefix() {
        return rolePrefix;
    }

    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    public boolean isRoleToUppercase() {
        return roleToUppercase;
    }

    public void setRoleToUppercase(boolean roleToUppercase) {
        this.roleToUppercase = roleToUppercase;
    }
}
