package au.org.ala.web;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * ALA User Details object, many properties are optional and could be null.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDetails implements Serializable {

    private static final long serialVersionUID = 45L;

    // Some old services return userId as an number id
    private Long id;

    private String firstName;
    private String lastName;
    private String userName;    // email
    private String userId;      // numeric id

    private String primaryUserType; // optional prop
    private String secondaryUserType; // optional prop
    private String organisation; // optional prop
    private String city; // optional prop
    private String state; // optional prop
    private String telephone; // optional prop
    private Boolean locked; // optional prop

    private Set<String> roles = new HashSet<String>();

    public String getUserId() {
        return userId != null ? userId : id != null ? String.valueOf(id) : null;
    }

    public String getEmail() {
        return userName;
    }

    public void setEmail(String email) {
        this.userName = email;
    }

    public String getDisplayName() {
        return firstName + " " + lastName;
    }

    /**
     * Returns true if the user represented by this UserDetails has the supplied role.
     * @param role the role to check.
     * @return true if this user has the supplied role.
     */
    boolean hasRole(String role) {
        return roles.contains(role);
    }
}
