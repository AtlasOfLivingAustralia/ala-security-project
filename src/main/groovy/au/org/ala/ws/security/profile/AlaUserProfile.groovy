package au.org.ala.ws.security.profile

import org.pac4j.core.profile.UserProfile

interface AlaUserProfile extends UserProfile {

    String getEmail()

    String getFirstName()

    String getLastName()
}
