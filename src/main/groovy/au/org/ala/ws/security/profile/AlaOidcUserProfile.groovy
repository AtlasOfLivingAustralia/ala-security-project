package au.org.ala.ws.security.profile

import org.pac4j.oidc.profile.OidcProfile

class AlaOidcUserProfile extends OidcProfile implements AlaUserProfile {

    @Override
    String getName() {
        return this.displayName
    }

    @Override
    String getGivenName() {
        return super.getFirstName()
    }
}
