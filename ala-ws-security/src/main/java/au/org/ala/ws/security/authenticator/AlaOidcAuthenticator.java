package au.org.ala.ws.security.authenticator;

import au.org.ala.ws.security.profile.AlaOidcUserProfile;
import au.org.ala.ws.security.profile.AlaUserProfile;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.pac4j.core.authorization.generator.AuthorizationGenerator;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.credentials.authenticator.UserInfoOidcAuthenticator;
import org.pac4j.oidc.profile.OidcProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Authenticator for JWT access_token based on the Pac4j {@link UserInfoOidcAuthenticator},
 * But instead it of using the userInfo endpoint to validate the access_token it uses OIDC metadata to get key information to validate JWT.
 * The scope parameter of {@link AccessToken} from the {@link OidcCredentials} is updated with the scope from the validated JWT access_token.
 * The credentials.userProfile is set to an instance of {@link AlaOidcUserProfile} a wrapped {@link OidcProfile} from the OIDC UserInfo endpoint.
 */
public class AlaOidcAuthenticator extends UserInfoOidcAuthenticator {

    public static final Logger log = LoggerFactory.getLogger(AlaOidcAuthenticator.class);

    public AlaOidcAuthenticator(final OidcConfiguration configuration) {
        super(configuration);
    }

    @Override
    protected void internalInit(boolean forceReinit) {

        super.internalInit(forceReinit);

        CommonHelper.assertNotNull("issuer", issuer);
        CommonHelper.assertTrue(CommonHelper.isNotEmpty(expectedJWSAlgs), "expectedJWSAlgs cannot be empty");
        CommonHelper.assertNotNull("keySource", keySource);
    }

    @Override
    public void validate(Credentials cred, WebContext context, SessionStore sessionStore) {

        init();

        final OidcCredentials credentials = (OidcCredentials) cred;
        final String accessToken = credentials.getAccessToken().getValue();
        final JWT jwt;
        try {
            jwt = JWTParser.parse(accessToken);
        } catch (ParseException e) {
            throw new CredentialsException("Cannot decrypt / verify JWT", e);
        }


        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<SecurityContext>();

        // Set the required "typ" header "at+jwt" for access tokens issued by the
        // Connect2id server, may not be set by other servers
//        jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(jwtType)));

// The expected JWS algorithm of the access tokens (agreed out-of-band)
//        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<SecurityContext>(expectedJWSAlgs, keySource);

//        JWEKeySelector<SecurityContext> jweKeySelector =
//                new JWEDecryptionKeySelector<>(expectedJWSAlgs, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);
//        jwtProcessor.setJWEDecrypterFactory();

        // Set the required JWT claims for access tokens issued by the server
        // TODO externalise the required claims
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(new JWTClaimsSet.Builder().issuer(issuer.getValue()).build(), Set.copyOf(requiredClaims)));

        String userId = null;
        Collection<String> accessTokenRoles;

        try {

            JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null);
            userId = (String) claimsSet.getClaim(userIdClaim);

            accessTokenRoles = getRoles(claimsSet);

            var scopeClaim = claimsSet.getClaim(OidcConfiguration.SCOPE);
            Scope scope;
            if (scopeClaim == null) {
                scope = null;
            } else if (scopeClaim instanceof String) {
                scope = Scope.parse((String)scopeClaim);
            } else if (scopeClaim instanceof Collection) {
                scope = Scope.parse((Collection<String>)scopeClaim);
            } else {
                throw new CredentialsException("Internal error parsing token scopes: " + accessToken);
            }
            credentials.setAccessToken(new BearerAccessToken(accessToken, 0L, scope));

        } catch (BadJOSEException e) {
            throw new CredentialsException("JWT Verification failed: " + accessToken, e);
        } catch (JOSEException e) {
            throw new CredentialsException("Internal error parsing token: " + accessToken, e);
        }

        if (requiredScopes != null && !requiredScopes.isEmpty()) {

            boolean scopesMatch = requiredScopes.stream().allMatch( requiredScope ->
                    credentials.getAccessToken().getScope().stream().anyMatch( scope ->
                            requiredScope.equals(scope.getValue())));
            if (!scopesMatch) {
                log.info("access_token scopes '" + credentials.getAccessToken().getScope() + "' is missing required scopes " + getRequiredScopes());
                throw new CredentialsException("access_token with scope '" + credentials.getAccessToken().getScope() + "' is missing required scopes " + getRequiredScopes());
            }
        }

        var accessTokenScope = credentials.getAccessToken().getScope();
        var accessTokenScopeSet = accessTokenScope != null ?
                accessTokenScope.stream().map(Identifier::getValue).collect(Collectors.toSet()) :
                Collections.<String>emptySet();


        if (accessTokenScope != null && accessTokenScope.contains(OIDCScopeValue.PROFILE)) {

            TokenCredentials tokenCredentials = new TokenCredentials(accessToken);
            super.validate(tokenCredentials, context, sessionStore);

            UserProfile profile = tokenCredentials.getUserProfile();

            if (authorizationGenerator != null) {
                final String finalUserId = userId;
                cred.setUserProfile(
                        authorizationGenerator.generate(context, sessionStore, profile)
                                .map( userProfile -> this.generateAlaUserProfile(finalUserId, userProfile, accessTokenScopeSet) ).get());
            } else {
                cred.setUserProfile(generateAlaUserProfile(userId, profile, accessTokenScopeSet));
            }

            if (accessTokenRoles != null && !accessTokenRoles.isEmpty()) {
                cred.getUserProfile().addRoles(accessTokenRoles);
            }

        } else if (userId != null && !userId.isEmpty()) {

            AlaOidcUserProfile alaOidcUserProfile = new AlaOidcUserProfile(userId);
            if (accessTokenRoles != null && !accessTokenRoles.isEmpty()) {
                alaOidcUserProfile.addRoles(accessTokenRoles);
            }
            alaOidcUserProfile.addPermissions(accessTokenScopeSet);

            cred.setUserProfile(alaOidcUserProfile);
        }

    }

    public AlaUserProfile generateAlaUserProfile(String userId, UserProfile profile, Set<String> accessTokenScopeSet) {

        AlaOidcUserProfile alaOidcUserProfile = new AlaOidcUserProfile(userId);
        alaOidcUserProfile.addAttributes(profile.getAttributes());
        alaOidcUserProfile.setRoles(profile.getRoles());
        alaOidcUserProfile.setPermissions(profile.getPermissions());
        alaOidcUserProfile.addPermissions(accessTokenScopeSet);

        return alaOidcUserProfile;
    }

    Collection<String> getRoles(JWTClaimsSet claimsSet) {

        if (!rolesFromAccessToken) {
            return List.of();
        }

        Stream<String> roles = accessTokenRoleClaims.stream()
                .map(claimsSet::getClaim)
                .filter(Objects::nonNull)
                .flatMap((Object roleClaim) -> {
                    Stream<String> result;
                    if (roleClaim instanceof String) {
                        result = Stream.of(((String)roleClaim).split(Pattern.quote(",")));
                    } else if (roleClaim.getClass().isArray() && roleClaim.getClass().getComponentType().isAssignableFrom(String.class)) {
                        result = Stream.of((String[])roleClaim);
                    } else if (Collection.class.isAssignableFrom(roleClaim.getClass())) {
                        result = ((Collection<String>) roleClaim).stream();
                    } else {
                        log.debug("Couldn't parse role claim value: {}", roleClaim);
                        result = Stream.empty();
                    }
                    return result;
                });

        if (this.rolePrefix != null && !this.rolePrefix.trim().isEmpty()) {
            roles = roles.map( role -> role.startsWith(this.rolePrefix) ? role : this.rolePrefix + role );
        }

        if (this.roleToUppercase) {
            roles = roles.map(String::toUpperCase);
        }

        return roles.collect(Collectors.toSet());
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("AlaOidcAuthenticator{");
        sb.append("issuer='").append(issuer).append("'");
//        sb.append(", jwtType='").append(jwtType).append('\'')
        sb.append(", expectedJWSAlgs=").append(expectedJWSAlgs);
        sb.append(", keySource=").append(keySource);
//        sb.append(", realmName='").append(realmName).append('\'')
//        sb.append(", expirationTime=").append(expirationTime)
//        sb.append(", identifierGenerator=").append(identifierGenerator)
        sb.append("}");
        return sb.toString();
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

    public AuthorizationGenerator getAuthorizationGenerator() {
        return authorizationGenerator;
    }

    public void setAuthorizationGenerator(AuthorizationGenerator authorizationGenerator) {
        this.authorizationGenerator = authorizationGenerator;
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

    private Issuer issuer;
    private Set<JWSAlgorithm> expectedJWSAlgs;
    private JWKSource<SecurityContext> keySource;
    private AuthorizationGenerator authorizationGenerator;
    private String userIdClaim;
    private List<String> requiredClaims;
    private List<String> requiredScopes;
    List<String> accessTokenRoleClaims;
    boolean rolesFromAccessToken = false;
    String rolePrefix = "";
    boolean roleToUppercase = true;
}
