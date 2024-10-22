package au.org.ala.web.pac4j;

import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.authorization.generator.AuthorizationGenerator;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.profile.UserProfile;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.StringTokenizer;

/**
 * Copy of the pac4j FromAttributesAuthorizationGenerator that applies the transform in convertProvidedRoleName to role
 * names before adding them to the user profile.
 */
public class ConvertingFromAttributesAuthorizationGenerator implements AuthorizationGenerator {


    private Collection<String> roleAttributes;

    private Collection<String> permissionAttributes;

    private String splitChar = ",";

    private String rolePrefix;
    private boolean convertRolesToUpperCase;

    public ConvertingFromAttributesAuthorizationGenerator() {
        this.roleAttributes = new ArrayList<>();
        this.permissionAttributes = new ArrayList<>();
        this.rolePrefix = "";
        this.convertRolesToUpperCase = true;
    }

    public ConvertingFromAttributesAuthorizationGenerator(final Collection<String> roleAttributes, final Collection<String> permissionAttributes, String rolePrefix, boolean convertRolesToUpperCase) {
        this.roleAttributes = roleAttributes;
        this.permissionAttributes = permissionAttributes;
        this.rolePrefix = rolePrefix;
        this.convertRolesToUpperCase = convertRolesToUpperCase;
    }

    public ConvertingFromAttributesAuthorizationGenerator(final String[] roleAttributes, final String[] permissionAttributes, String rolePrefix, boolean convertRolesToUpperCase) {
        this.rolePrefix = rolePrefix;
        this.convertRolesToUpperCase = convertRolesToUpperCase;
        if (roleAttributes != null) {
            this.roleAttributes = Arrays.asList(roleAttributes);
        } else {
            this.roleAttributes = null;
        }
        if (permissionAttributes != null) {
            this.permissionAttributes = Arrays.asList(permissionAttributes);
        } else {
            this.permissionAttributes = null;
        }
    }

    @Override
    public Optional<UserProfile> generate(CallContext callContext, UserProfile profile) {
        generateAuth(profile, this.roleAttributes, true);
        generateAuth(profile, this.permissionAttributes, false);
        return Optional.of(profile);
    }

    private void generateAuth(final UserProfile profile, final Iterable<String> attributes, final boolean isRole) {
        if (attributes == null) {
            return;
        }

        for (final var attribute : attributes) {
            final var value = profile.getAttribute(attribute);
            if (value != null) {
                if (value instanceof String) {
                    final var st = new StringTokenizer((String) value, this.splitChar);
                    while (st.hasMoreTokens()) {
                        addRoleOrPermissionToProfile(profile, st.nextToken(), isRole);
                    }
                } else if (value.getClass().isArray() && value.getClass().getComponentType().isAssignableFrom(String.class)) {
                    for (var item : (Object[]) value) {
                        addRoleOrPermissionToProfile(profile, item.toString(), isRole);
                    }
                } else if (Collection.class.isAssignableFrom(value.getClass())) {
                    for (Object item : (Collection<?>) value) {
                        if (item.getClass().isAssignableFrom(String.class)) {
                            addRoleOrPermissionToProfile(profile, item.toString(), isRole);
                        }
                    }
                }
            }
        }

    }

    private void addRoleOrPermissionToProfile(final UserProfile profile, final String value, final boolean isRole) {
        if (isRole) {
            profile.addRole(convertProvidedRoleName(value));
        } else {
            // TODO what to do with this?
//            profile.addPermission(value);
        }
    }

    private String convertProvidedRoleName(String role) {
        String result = !StringUtils.isBlank(rolePrefix) ? (rolePrefix + role) : role;
        return convertRolesToUpperCase ? result.toUpperCase() : result;
    }

    public String getSplitChar() {
        return this.splitChar;
    }

    public void setSplitChar(final String splitChar) {
        this.splitChar = splitChar;
    }

    public void setRoleAttributes(final String roleAttributesStr) {
        this.roleAttributes = Arrays.asList(roleAttributesStr.split(splitChar));
    }

    public void setPermissionAttributes(final String permissionAttributesStr) {
        this.permissionAttributes = Arrays.asList(permissionAttributesStr.split(splitChar));
    }

}
