package au.org.ala.ws.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.profile.ProfileHelper;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.profile.creator.AuthenticatorProfileCreator;
import org.pac4j.core.profile.definition.ProfileDefinitionAware;
import org.pac4j.core.profile.jwt.JwtClaims;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.core.util.generator.ValueGenerator;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.jwt.profile.JwtProfileDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.pac4j.core.util.CommonHelper.assertNotBlank;
import static org.pac4j.core.util.CommonHelper.toNiceString;

/**
 * Authenticator for JWT. Based on the Pac4j {@link org.pac4j.jwt.credentials.authenticator.JwtAuthenticator},
 * but instead it uses OIDC metadata to get key information to validate JWTs.
 * It creates the user profile and stores it in the credentials
 * for the {@link AuthenticatorProfileCreator}.
 *
 */
public class JwtAuthenticator extends ProfileDefinitionAware implements Authenticator {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private String issuer;
    private String jwtType = "jwt";
    private Set<JWSAlgorithm> expectedJWSAlgs;
    // The public RSA keys to validate the signatures will be sourced from the
    // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
    // object caches the retrieved keys to speed up subsequent look-ups and can
    // also handle key-rollover
    JWKSource<SecurityContext> keySource;

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME;

    private Date expirationTime;

    private ValueGenerator identifierGenerator;

    public JwtAuthenticator(String issuer, Set<JWSAlgorithm> expectedJWSAlgs, JWKSource<SecurityContext> keySource) {
        this.issuer = issuer;
        this.expectedJWSAlgs = expectedJWSAlgs;
        this.keySource = keySource;
    }

    @Override
    protected void internalInit(final boolean forceReinit) {
        assertNotBlank("realmName", this.realmName);
        defaultProfileDefinition(new JwtProfileDefinition());
    }

    /**
     * Validates the token and returns the corresponding user profile.
     *
     * @param token the JWT
     * @return the corresponding user profile
     */
    public Map<String, Object> validateTokenAndGetClaims(final String token) {
        final var profile = validateToken(token);

        final Map<String, Object> claims = new HashMap<>(profile.getAttributes());
        claims.put(JwtClaims.SUBJECT, profile.getId());

        return claims;
    }

    /**
     * Validates the token and returns the corresponding user profile.
     *
     * @param token the JWT
     * @return the corresponding user profile
     */
    public UserProfile validateToken(final String token) {
        final var credentials = new TokenCredentials(token);
        try {
            validate(credentials, null, null);
        } catch (final HttpAction e) {
            throw new TechnicalException(e);
        } catch (final CredentialsException e) {
            logger.info("Failed to retrieve or validate credentials: {}", e.getMessage());
            logger.debug("Failed to retrieve or validate credentials", e);
            return null;
        }
        return credentials.getUserProfile();
    }

    @Override
    public void validate(final Credentials cred, final WebContext context, final SessionStore sessionStore) {
        init();

        final var credentials = (TokenCredentials) cred;
        final var token = credentials.getToken();
        final JWT jwt;
        try {
            jwt = JWTParser.parse(token);
        } catch (ParseException e) {
            throw new CredentialsException("Cannot decrypt / verify JWT", e);
        }

        if (context != null) {
            // set the www-authenticate in case of error
            context.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, "Bearer realm=\"" + realmName + "\"");
        }

        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // Set the required "typ" header "at+jwt" for access tokens issued by the
        // Connect2id server, may not be set by other servers
        jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(jwtType)));

// The expected JWS algorithm of the access tokens (agreed out-of-band)
//        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(expectedJWSAlgs, keySource);

//        JWEKeySelector<SecurityContext> jweKeySelector =
//                new JWEDecryptionKeySelector<>(expectedJWSAlgs, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);
//        jwtProcessor.setJWEDecrypterFactory();

        // Set the required JWT claims for access tokens issued by the server
        // TODO externalise the required claims
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder().issuer(issuer).build(),
                new HashSet<>(Arrays.asList("sub", "iat", "exp", "nbf", "scp", "cid", "jti"))));

    // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet;
        try {
            claimsSet = jwtProcessor.process(jwt, ctx);
        } catch (BadJOSEException e) {
//            if (logger.isDebugEnabled()) {
//                logger.debug("JWT Verification failed: {}", token, e);
//            } else {
//                logger.warn("JWT Verification failed: {}", token);
//            }
            throw new CredentialsException("JWT Verification failed: " + token, e);
        } catch (JOSEException e) {
            throw new CredentialsException("Internal error parsing token: " + token, e);
        }

        createJwtProfile(credentials, claimsSet, context, sessionStore);

    }

    @SuppressWarnings("unchecked")
    protected void createJwtProfile(final TokenCredentials credentials, final JWTClaimsSet claimSet, final WebContext context,
                                    final SessionStore sessionStore) {

        var subject = claimSet.getSubject();
        if (subject == null) {
            if (identifierGenerator != null) {
                subject = identifierGenerator.generateValue(context, sessionStore);
            }
            if (subject == null) {
                throw new TechnicalException("The JWT must contain a subject or an id must be generated via the identifierGenerator");
            }
        }

        final var expTime = claimSet.getExpirationTime();
        if (expTime != null) {
            final var now = new Date();
            if (expTime.before(now)) {
                logger.error("The JWT is expired: no profile is built");
                return;
            }
            if (this.expirationTime != null && expTime.after(this.expirationTime)) {
                logger.error("The JWT is expired: no profile is built");
                return;
            }
        }

        final Map<String, Object> attributes = new HashMap<>(claimSet.getClaims());
        attributes.remove(JwtClaims.SUBJECT);

        final var roles = (List<String>) attributes.get(JwtGenerator.INTERNAL_ROLES);
        attributes.remove(JwtGenerator.INTERNAL_ROLES);
        final var permissions = (List<String>) attributes.get(JwtGenerator.INTERNAL_PERMISSIONS);
        attributes.remove(JwtGenerator.INTERNAL_PERMISSIONS);
        final var linkedId = (String) attributes.get(JwtGenerator.INTERNAL_LINKEDID);
        attributes.remove(JwtGenerator.INTERNAL_LINKEDID);

        final var profile = getProfileDefinition().newProfile(subject);
        profile.setId(ProfileHelper.sanitizeIdentifier(subject));
        getProfileDefinition().convertAndAdd(profile, attributes, null);

        if (roles != null) {
            profile.addRoles(roles);
        }
        if (permissions != null) {
            profile.addPermissions(permissions);
        }
        if (linkedId != null) {
            profile.setLinkedId(linkedId);
        }
        credentials.setUserProfile(profile);
    }

    public String getRealmName() {
        return realmName;
    }

    public void setRealmName(final String realmName) {
        this.realmName = realmName;
    }

    public void setExpirationTime(final Date expirationTime) {
        this.expirationTime = new Date(expirationTime.getTime());
    }

    public Date getExpirationTime() {
        return new Date(expirationTime.getTime());
    }

    public ValueGenerator getIdentifierGenerator() {
        return identifierGenerator;
    }

    public void setIdentifierGenerator(final ValueGenerator identifierGenerator) {
        this.identifierGenerator = identifierGenerator;
    }


    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getJwtType() {
        return jwtType;
    }

    public void setJwtType(String jwtType) {
        this.jwtType = jwtType;
    }

    public JWKSource<SecurityContext> getKeySource() {
        return keySource;
    }

    public void setKeySource(JWKSource<SecurityContext> keySource) {
        this.keySource = keySource;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("JwtAuthenticator{");
        sb.append("issuer='").append(issuer).append('\'');
        sb.append(", jwtType='").append(jwtType).append('\'');
        sb.append(", expectedJWSAlgs=").append(expectedJWSAlgs);
        sb.append(", keySource=").append(keySource);
        sb.append(", realmName='").append(realmName).append('\'');
        sb.append(", expirationTime=").append(expirationTime);
        sb.append(", identifierGenerator=").append(identifierGenerator);
        sb.append('}');
        return sb.toString();
    }

    //    @Override
//    public String toString() {
//        return toNiceString(this.getClass(),
//                "realmName", this.realmName,
//                "identifierGenerator", this.identifierGenerator);
//    }

}
