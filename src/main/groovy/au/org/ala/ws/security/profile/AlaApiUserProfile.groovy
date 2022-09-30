package au.org.ala.ws.security.profile

class AlaApiUserProfile extends AlaUserProfile {

    boolean activated = true
    boolean locked = false

    AlaApiUserProfile() {}

    AlaApiUserProfile(String userId, String email, String firstName, String lastName, Set<String> roles, Map<String, Object> attributes) {
        super(userId, email, firstName, lastName, roles, attributes)
    }
}
