package au.org.ala.web;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.beans.ConstructorProperties;
import java.io.Serializable;
import java.util.*;

/**
 * ALA User Details object, many properties are optional and could be null.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor()
public class UserDetails implements Serializable {

    public static final String PRIMARY_USER_TYPE_PROPERTY = "primaryUserType";
    public static final String SECONDARY_USER_TYPE_PROPERTY = "secondaryUserType";
    public static final String ORGANISATION_PROPERTY = "organisation";
    public static final String CITY_PROPERTY = "city";
    public static final String STATE_PROPERTY = "state";
    public static final String COUNTRY_PROPERTY = "country";
    public static final String TELEPHONE_PROPERTY = "telephone";

    private static final long serialVersionUID = 46L;

    // Some old services return userId as an number id
    private Long id;

    private String firstName;
    private String lastName;
    private String userName;    // email
    private String userId;      // numeric id
    private Boolean locked;
    private Boolean activated;

    private Map<String, String> props = new LinkedHashMap<>(); // optional props

    private Set<String> roles = new HashSet<String>();

    @ConstructorProperties({"id", "firstName", "lastName", "userName", "userId", "locked", "roles"})
    public UserDetails(Long id, String firstName, String lastName, String userName, String userId, Boolean locked, Set<String> roles) {
        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
        this.userName = userName;
        this.userId = userId;
        this.locked = locked;
        this.roles = roles;
    }

    @ConstructorProperties({"id", "firstName", "lastName", "userName", "userId", "locked", "primaryUserType", "secondaryUserType", "organisation", "city", "state", "telephone", "roles"})
    public UserDetails(Long id, String firstName, String lastName, String userName, String userId, Boolean locked, @Deprecated String primaryUserType, @Deprecated String secondaryUserType, String organisation, String city, String state, @Deprecated String telephone, Set<String> roles) {
        this(id, firstName, lastName, userName, userId, locked, roles);
        setPrimaryUserType(primaryUserType);
        setSecondaryUserTypeProperty(secondaryUserType);
        setOrganisation(organisation);
        setCity(city);
        setState(state);
        setTelephone(telephone);
    }

    @ConstructorProperties({"id", "firstName", "lastName", "userName", "userId", "locked", "organisation", "city", "state", "country", "roles"})
    public UserDetails(Long id, String firstName, String lastName, String userName, String userId, Boolean locked, String organisation, String city, String state, String country, Set<String> roles) {
        this(id, firstName, lastName, userName, userId, locked, roles);
        setOrganisation(organisation);
        setCity(city);
        setState(state);
        setCountry(country);
    }

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

    @Deprecated
    public String getPrimaryUserType() {
        return props.get(PRIMARY_USER_TYPE_PROPERTY);
    }

    @Deprecated
    public void setPrimaryUserType(String primaryUserType) {
        props.put(PRIMARY_USER_TYPE_PROPERTY, primaryUserType);
    }

    @Deprecated
    public String getSecondaryUserType() {
        return props.get(SECONDARY_USER_TYPE_PROPERTY);
    }

    @Deprecated
    public void setSecondaryUserTypeProperty(String secondaryUserType) {
        props.put(SECONDARY_USER_TYPE_PROPERTY, secondaryUserType);
    }

    public String getOrganisation() {
        return props.get(ORGANISATION_PROPERTY);
    }

    public void setOrganisation(String organisation) {
        props.put(ORGANISATION_PROPERTY, organisation);
    }

    public String getCity() {
        return props.get(CITY_PROPERTY);
    }

    public void setCity(String city) {
        props.put(CITY_PROPERTY, city);
    }

    public String getState() {
        return props.get(STATE_PROPERTY);
    }

    public void setState(String state) {
        props.put(STATE_PROPERTY, state);
    }

    public String getCountry() {
        return props.get(COUNTRY_PROPERTY);
    }

    public void setCountry(String country) {
        props.put(COUNTRY_PROPERTY, country);
    }

    @Deprecated
    public String getTelephone() {
        return props.get(TELEPHONE_PROPERTY);
    }

    @Deprecated
    public void setTelephone(String telephone) {
        props.put(TELEPHONE_PROPERTY, telephone);
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
