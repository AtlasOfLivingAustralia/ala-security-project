package au.org.ala.ws.security;

import org.springframework.security.core.AuthenticatedPrincipal;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Set;


public class AlaUser implements Principal, AuthenticatedPrincipal {

    String email;
    String userId;
    Set<String> roles = Collections.emptySet();
    Map<String, Object> attributes = Collections.emptyMap();
    String firstName;
    String lastName;

    public AlaUser(){}

    public AlaUser(String email, String userId, Set<String> roles, Map<String, Object> attributes, String firstName, String lastName) {
        this.email = email;
        this.userId = userId;
        this.roles = roles;
        this.attributes = attributes;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    @Override
    public String getName() {
        return email;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
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

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
}