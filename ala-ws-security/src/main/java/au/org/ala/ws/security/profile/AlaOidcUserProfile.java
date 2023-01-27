package au.org.ala.ws.security.profile;

import org.pac4j.oidc.profile.OidcProfile;

import java.security.Principal;

public class AlaOidcUserProfile extends OidcProfile implements AlaUserProfile {

    final String userId;

    public AlaOidcUserProfile(String userId) {
        this.userId = userId;
    }

    @Override
    public String getUserId() {
        return userId;
    }

    @Override
    public String getName() {
        return this.getDisplayName();
    }

    @Override
    public String getGivenName() {
        return super.getFirstName();
    }

    @Override
    public Principal asPrincipal() {
        return this;
    }
}
