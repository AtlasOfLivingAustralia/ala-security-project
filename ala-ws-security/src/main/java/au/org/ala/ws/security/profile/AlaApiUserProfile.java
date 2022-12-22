package au.org.ala.ws.security.profile;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class AlaApiUserProfile implements AlaUserProfile {
    public AlaApiUserProfile() {
    }

    public AlaApiUserProfile(String userId, String email, String givenName, String familyName, Set<String> roles, Map<String, Object> attributes) {
        this.email = email;
        this.userId = userId;
        this.roles = roles;
        this.attributes = attributes;
        this.givenName = givenName;
        this.familyName = familyName;
    }

    @Override
    public String getName() {
        return getUsername();
    }

    @Override
    public String getId() {
        return userId;
    }

    @Override
    public void setId(String id) {
        this.userId = id;
    }

    @Override
    public String getTypedId() {
        return null;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    @Override
    public boolean containsAttribute(String name) {
        return attributes.containsKey(name);
    }

    @Override
    public void addAttribute(String key, Object value) {
        attributes.put(key, value);
    }

    @Override
    public void removeAttribute(String key) {
        attributes.remove(key);
    }

    @Override
    public void addAuthenticationAttribute(String key, Object value) {
    }

    @Override
    public void removeAuthenticationAttribute(String key) {
    }

    @Override
    public void addRole(String role) {
        roles.add(role);
    }

    @Override
    public void addRoles(Collection<String> roles) {
        this.roles.addAll(roles);
    }

    @Override
    public void addPermission(String permission) {

    }

    @Override
    public void addPermissions(Collection<String> permissions) {

    }

    @Override
    public Set<String> getPermissions() {
        return Set.of();
    }

    @Override
    public boolean isRemembered() {
        return false;
    }

    @Override
    public void setRemembered(boolean rme) {

    }

    @Override
    public String getClientName() {
        return null;
    }

    @Override
    public void setClientName(String clientName) {

    }

    @Override
    public String getLinkedId() {
        return null;
    }

    @Override
    public void setLinkedId(String linkedId) {

    }

    @Override
    public boolean isExpired() {
        return false;
    }

    @Override
    public Principal asPrincipal() {

        return this;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean getActivated() {
        return activated;
    }

    public boolean isActivated() {
        return activated;
    }

    public void setActivated(boolean activated) {
        this.activated = activated;
    }

    public boolean getLocked() {
        return locked;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    private String userId;
    private String givenName;
    private String familyName;
    private String email;
    private boolean activated = true;
    private boolean locked = false;
    private Set<String> roles = new LinkedHashSet<>();
    private Map<String, Object> attributes = new LinkedHashMap<>();
}
