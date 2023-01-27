package au.org.ala.ws.security.profile;

import org.pac4j.core.profile.UserProfile;

import java.security.Principal;

public interface AlaUserProfile extends Principal, UserProfile {

    String getUserId();

    String getEmail();

    String getGivenName();

    String getFamilyName();
}
