package au.org.ala.ws.security.profile

import org.pac4j.core.profile.UserProfile

import java.security.Principal

interface AlaUserProfile extends Principal, UserProfile {

    String getEmail()

    String getGivenName()

    String getFamilyName()
}
