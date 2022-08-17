package au.org.ala.ws.security.profile

import java.security.Principal

class AlaApiUserProfile implements AlaUserProfile {

    String userId
    String firstName
    String lastName
    String email

    boolean activated = true
    boolean locked = false

    List<String> roles = Collections.emptyList()
    Map<String, Object> attributes = Collections.emptyMap()

    AlaApiUserProfile() {}

    AlaApiUserProfile(String userId, String email, String firstName, String lastName, List<String> roles, Map<String, Object> attributes) {
        this.email = email
        this.userId = userId
        this.roles = roles
        this.attributes = attributes
        this.firstName = firstName
        this.lastName = lastName
    }

    @Override
    String getEmail() {
        return email
    }

    @Override
    String getFirstName() {
        return firstName
    }

    @Override
    String getLastName() {
        return lastName
    }

    @Override
    String getId() {
        return userId
    }

    @Override
    void setId(String id) {
        this.userId = id
    }

    @Override
    String getTypedId() {
        return null
    }

    @Override
    String getUsername() {
        return null
    }

    @Override
    Object getAttribute(String name) {
        return attributes.get(name)
    }

    @Override
    Map<String, Object> getAttributes() {
        return attributes
    }

    @Override
    boolean containsAttribute(String name) {
        return attributes.containsKey(name)
    }

    @Override
    void addAttribute(String key, Object value) {
        attributes.put(key, value)
    }

    @Override
    void removeAttribute(String key) {
        attributes.remove(key)
    }

    @Override
    void addAuthenticationAttribute(String key, Object value) {
    }

    @Override
    void removeAuthenticationAttribute(String key) {
    }

    @Override
    void addRole(String role) {
        roles.add(role)
    }

    @Override
    void addRoles(Collection<String> roles) {
        roles.addAll(roles)
    }

    @Override
    Set<String> getRoles() {
        return roles
    }

    @Override
    void addPermission(String permission) {

    }

    @Override
    void addPermissions(Collection<String> permissions) {

    }

    @Override
    Set<String> getPermissions() {
        return Set.of()
    }

    @Override
    boolean isRemembered() {
        return false
    }

    @Override
    void setRemembered(boolean rme) {

    }

    @Override
    String getClientName() {
        return null
    }

    @Override
    void setClientName(String clientName) {

    }

    @Override
    String getLinkedId() {
        return null
    }

    @Override
    void setLinkedId(String linkedId) {

    }

    @Override
    boolean isExpired() {
        return false
    }

    @Override
    Principal asPrincipal() {

        return new Principal() {
            @Override
            String getName() { return email }
        }
    }
}
