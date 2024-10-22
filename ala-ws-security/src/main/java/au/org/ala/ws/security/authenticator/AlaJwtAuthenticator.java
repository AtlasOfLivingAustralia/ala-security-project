package au.org.ala.ws.security.authenticator;

import au.org.ala.ws.security.credentials.JwtCredentials;
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
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.profile.ProfileHelper;
import org.pac4j.core.profile.definition.ProfileDefinitionAware;
import org.pac4j.core.profile.jwt.JwtClaims;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.core.util.generator.ValueGenerator;
import org.pac4j.jwt.profile.JwtGenerator;
import org.pac4j.jwt.profile.JwtProfileDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.pac4j.core.util.CommonHelper.assertNotBlank;
import static org.pac4j.oidc.config.OidcConfiguration.SCOPE;

/**
 * Copy of the JwtAuthenticator with support for using the JWKS from the OICD
 * configuration and includes additional validation of the JWT such as required scopes, required issuer and
 * required audience.
 */
public class AlaJwtAuthenticator extends ProfileDefinitionAware implements Authenticator {

    public static final Logger logger = LoggerFactory.getLogger(AlaJwtAuthenticator.class);

    public static final String PARSED_JWT_ATTRIBUTE = "ala.parsed.jwt";

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME;

//    private Date expirationTime;

//    private ValueGenerator identifierGenerator;

    private Set<String> acceptedAudiences = Collections.emptySet();
    private Issuer issuer;
    private Set<JWSAlgorithm> expectedJWSAlgs;
    private JWKSource<SecurityContext> keySource;
    private List<String> requiredClaims;
    private List<String> prohibitedClaims = Collections.emptyList();
    private List<String> requiredScopes;

    private Date expirationTime;
    private ValueGenerator identifierGenerator;

    public AlaJwtAuthenticator() {
        super();
    }

    @Override
    protected void internalInit(final boolean forceReinit) {
        assertNotBlank("realmName", this.realmName);
        setProfileDefinitionIfUndefined(new JwtProfileDefinition());

    }

    @Override
    public Optional<Credentials> validate(CallContext ctx, Credentials cred) {
        init();

        var credentials = (TokenCredentials) cred;
        var token = credentials.getToken();

        if (ctx != null) {
            var webContext = ctx.webContext();
            if (webContext != null) {
                // set the www-authenticate in case of error
                webContext.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, "Bearer realm=\"" + realmName + "\"");
            }
        }

        try {
            // Parse the token
            var jwt = JWTParser.parse(token);

            // Create a JWT processor for the access tokens
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<SecurityContext>();
            // Configure the JWT processor with a key selector to feed matching public
            // RSA keys sourced from the JWK set URL
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<SecurityContext>(expectedJWSAlgs, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);

            // Set the required JWT claims for access tokens issued by the server
            // TODO externalise the required claims
            jwtProcessor.setJWTClaimsSetVerifier(
                    new DefaultJWTClaimsVerifier(
                            acceptedAudiences == null || acceptedAudiences.isEmpty() ? null : Set.copyOf(acceptedAudiences),
                            new JWTClaimsSet.Builder()
                                    .issuer(issuer.getValue())
                                    .build(),
                            Set.copyOf(requiredClaims),
                            Set.copyOf(prohibitedClaims)
                    )
            );

            jwtProcessor.process(jwt, null);

            createJwtProfile(ctx, credentials, jwt);

            return Optional.of(new JwtCredentials(token, jwt));

        } catch (final ParseException | BadJOSEException | JOSEException e) {
            throw new CredentialsException("Cannot decrypt / verify JWT", e);
        }
    }

    protected void createJwtProfile(CallContext ctx, TokenCredentials credentials, JWT jwt) throws ParseException {
        var claimSet = jwt.getJWTClaimsSet();
        var subject = claimSet.getSubject();
        if (subject == null) {
            if (getIdentifierGenerator() != null) {
                subject = getIdentifierGenerator().generateValue(ctx);
            }
            if (subject == null) {
                throw new TechnicalException("The JWT must contain a subject or an id must be generated via the identifierGenerator");
            }
        }

        var expTime = claimSet.getExpirationTime();
        if (expTime != null) {
            var now = new Date();
            if (expTime.before(now)) {
                logger.warn("The JWT is expired: no profile is built");
                return;
            }
            if (this.expirationTime != null && expTime.after(this.expirationTime)) {
                logger.warn("The JWT is expired: no profile is built");
                return;
            }
        }

        var attributes = new HashMap<>(claimSet.getClaims());
        attributes.remove(JwtClaims.SUBJECT);

        Collection<String> roles = (List<String>) attributes.get(JwtGenerator.INTERNAL_ROLES);
        attributes.remove(JwtGenerator.INTERNAL_ROLES);
        var linkedId = (String) attributes.get(JwtGenerator.INTERNAL_LINKEDID);
        attributes.remove(JwtGenerator.INTERNAL_LINKEDID);

        var profile = getProfileDefinition().newProfile(subject);
        profile.setId(ProfileHelper.sanitizeIdentifier(subject));
        getProfileDefinition().convertAndAdd(profile, attributes, null);

        if (roles != null) {
            profile.addRoles(roles);
        }
        if (linkedId != null) {
            profile.setLinkedId(linkedId);
        }

        // Additional ALA code

        if (ctx != null) {
            ctx.webContext().setRequestAttribute(PARSED_JWT_ATTRIBUTE, jwt);
        } else {
            logger.debug("Not saving parsed JWT to request attribute because the context is null");
        }

        if (requiredScopes != null && !requiredScopes.isEmpty()) {

            var scopeClaim = jwt.getJWTClaimsSet().getClaim(SCOPE);
            Scope scope;
            if (scopeClaim == null) {
                scope = null;
            } else if (scopeClaim instanceof String) {
                scope = Scope.parse((String) scopeClaim);
            } else if (scopeClaim instanceof Collection) {
                scope = Scope.parse((Collection<String>) scopeClaim);
            } else {
                throw new CredentialsException("Internal error parsing token scopes: " + scopeClaim);
            }

            final List<String> scopeList;
            if (scope != null) {
                scopeList = scope.toStringList();
            } else {
                scopeList = new ArrayList<>();
            }

            boolean scopesMatch = requiredScopes.stream().allMatch(requiredScope ->
                    scopeList.stream().anyMatch(requiredScope::equals)
            );
            if (!scopesMatch) {
                logger.info("access_token scopes '{}' is missing required scopes {}", scopeList, requiredScopes);
                throw new CredentialsException("access_token with scope '" + scopeList + "' is missing required scopes " + requiredScopes);
            }
        }

        credentials.setUserProfile(profile);
    }


    public Set<String> getAcceptedAudiences() {
        return acceptedAudiences;
    }

    public void setAcceptedAudiences(Set<String> acceptedAudiences) {
        this.acceptedAudiences = acceptedAudiences;
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

    /**
     * <p>Setter for the field <code>expirationTime</code>.</p>
     *
     * @param expirationTime a {@link Date} object
     */
    public void setExpirationTime(final Date expirationTime) {
        this.expirationTime = expirationTime != null ? new Date(expirationTime.getTime()) : null;
    }

    /**
     * <p>Getter for the field <code>expirationTime</code>.</p>
     *
     * @return a {@link Date} object
     */
    public Date getExpirationTime() {
        return expirationTime != null ? new Date(expirationTime.getTime()) : null ;
    }

    public ValueGenerator getIdentifierGenerator() {
        return identifierGenerator;
    }

    public void setIdentifierGenerator(ValueGenerator identifierGenerator) {
        this.identifierGenerator = identifierGenerator;
    }
}
