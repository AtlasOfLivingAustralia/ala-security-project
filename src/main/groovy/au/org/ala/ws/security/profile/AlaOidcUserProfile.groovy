package au.org.ala.ws.security.profile

import org.pac4j.oidc.profile.OidcProfile
import org.pac4j.oidc.profile.OidcProfileDefinition

import java.security.Principal

class AlaOidcUserProfile implements AlaUserProfile {

    OidcProfile delegate

    AlaOidcUserProfile(OidcProfile delegate) {
        this.delegate = delegate
    }

    @Override
    String getEmail() {
        return delegate.getEmail()
    }

    @Override
    String getFirstName() {
        return delegate.getFirstName()
    }

    String getLastName() {
        getFamilyName()
    }

    String getFamilyName() {
        delegate.getAttribute(OidcProfileDefinition.FAMILY_NAME)
    }

    @Override
    String getId() {
        return delegate.id
    }

    @Override
    void setId(String id) {
        delegate.id = id
    }

    @Override
    String getTypedId() {
        return delegate.typedId
    }

    @Override
    String getUsername() {
        return delegate.username
    }

    @Override
    Object getAttribute(String name) {
        return delegate.getAttribute(name)
    }

    @Override
    Map<String, Object> getAttributes() {
        return delegate.attributes
    }

    @Override
    boolean containsAttribute(String name) {
        return delegate.containsAttribute(name)
    }

    @Override
    void addAttribute(String key, Object value) {
        delegate.addAttribute(key, name)
    }

    @Override
    void removeAttribute(String key) {
        delegate.removeAttribute(key)
    }

    @Override
    void addAuthenticationAttribute(String key, Object value) {
        delegate.addAuthenticationAttribute(key, value)
    }

    @Override
    void removeAuthenticationAttribute(String key) {
        delegate.removeAuthenticationAttribute(key)
    }

    @Override
    void addRole(String role) {
        delegate.addRole(role)
    }

    @Override
    void addRoles(Collection<String> roles) {
        delegate.addRoles(roles)
    }

    @Override
    Set<String> getRoles() {
        return delegate.roles
    }

    @Override
    void addPermission(String permission) {
        delegate.addPermission(permission)
    }

    @Override
    void addPermissions(Collection<String> permissions) {
        delegate.addPermissions(permissions)
    }

    @Override
    Set<String> getPermissions() {
        return delegate.permissions
    }

    @Override
    boolean isRemembered() {
        return delegate.remembered
    }

    @Override
    void setRemembered(boolean rme) {
        delegate.remembered = rme
    }

    @Override
    String getClientName() {
        return delegate.clientName
    }

    @Override
    void setClientName(String clientName) {
        delegate.clientName = clientName
    }

    @Override
    String getLinkedId() {
        return delegate.linkedId
    }

    @Override
    void setLinkedId(String linkedId) {
        delegate.linkedId = linkedId
    }

    @Override
    boolean isExpired() {
        return delegate.expired
    }

    @Override
    Principal asPrincipal() {
        return delegate.asPrincipal()
    }
}
