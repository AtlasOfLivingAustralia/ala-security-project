package au.org.ala.ws.security.profile;

import org.pac4j.oidc.profile.OidcProfile;

public class AlaOidcUserProfile extends OidcProfile implements AlaUserProfile {
    @Override
    public String getName() {
        return this.getDisplayName();
    }

    @Override
    public String getGivenName() {
        return super.getFirstName();
    }

}
