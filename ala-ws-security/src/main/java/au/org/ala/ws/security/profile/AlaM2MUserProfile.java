package au.org.ala.ws.security.profile;

import org.pac4j.oidc.profile.OidcProfile;

import java.util.List;

/**
 * User profile for Client Credentials tokens
 */
public class AlaM2MUserProfile extends AlaOidcUserProfile {

    private final String clientId;
    private final String issuer;
    private final List<String> audience;

    public AlaM2MUserProfile(String clientId, String issuer, List<String> audience) {
        super(clientId);
        this.clientId = clientId;
        this.issuer = issuer;
        this.audience = audience;
    }

    @Override
    public String getGivenName() {
        return clientId;
    }

    @Override
    public String getName() {
        return clientId;
    }

    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public List<String> getAudience() {
        return audience;
    }
}
