package au.org.ala.web

import grails.web.mapping.LinkGenerator
import org.pac4j.core.config.Config
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.UserProfile
import org.springframework.beans.factory.annotation.Autowired

class Pac4jAuthService implements IAuthService {

    // TODO Make these configurable?
    // OIDC openid scope attrs
    static final String ATTR_SUB = 'sub'
    // OIDC email scope attrs
    static final String ATTR_EMAIL = 'email'
    static final String ATTR_EMAIL_VERIFIED = 'email_verified'
    // OIDC profile scope attrs
    static final String ATTR_NAME = 'name'
    static final String ATTR_FIRST_NAME = 'given_name'
    static final String ATTR_MIDDLE_NAME = 'middle_name'
    static final String ATTR_LAST_NAME = 'family_name'
    static final String ATTR_NICKNAME = 'nickname'
    static final String ATTR_PICTURE = 'picture'
    static final String ATTR_UPDATED_AT = 'updated_at'

    // fallback ALA CAS attributes
    static final String ATTR_CAS_FIRST_NAME = 'firstname'
    static final String ATTR_CAS_LAST_NAME = 'sn'

    // ALA scoped attributes
    static final String ATTR_ROLE = 'role'
    static final String ATTR_ROLES = 'roles'

    static final String ATTR_USERID = 'userid'

    @Autowired
    private final Config config

    @Autowired
    private final Pac4jContextProvider pac4jContextProvider

    @Autowired
    private final SessionStore sessionStore

    @Autowired
    private final LinkGenerator grailsLinkGenerator

    Pac4jAuthService(Config config, Pac4jContextProvider pac4jContextProvider, SessionStore sessionStore, LinkGenerator grailsLinkGenerator) {
        this.config = config
        this.pac4jContextProvider = pac4jContextProvider
        this.sessionStore = sessionStore
        this.grailsLinkGenerator = grailsLinkGenerator
    }

    ProfileManager getProfileManager() {
        def context = pac4jContextProvider.webContext()
        final ProfileManager manager = new ProfileManager(context, sessionStore)
        manager.config = config
        return manager
    }

    UserProfile getUserProfile() {
        def manager = profileManager

        def value = null
        if (manager.authenticated) {
            final Optional<UserProfile> profile = manager.getProfile()
            if (profile.isPresent()) {
                value = profile.get()
            }
        }
        return value
    }

    String getAttribute(String attribute) {
        def manager = profileManager

        def value = null
        if (manager.authenticated) {
            final Optional<UserProfile> profile = manager.getProfile()
            if (profile.isPresent()) {
                def userProfile = profile.get()
                if (userProfile) {
                    value = userProfile.getAttribute(attribute)
                }
            }
        }
        return value
    }

    @Override
    String getEmail() {
        return getAttribute(ATTR_EMAIL)
    }

    @Override
    String getUserId() {
        def manager = profileManager
        def value = null
        if (manager.authenticated) {
            final Optional<UserProfile> profile = manager.getProfile()
            if (profile.isPresent()) {
                def userProfile = profile.get()
                if (userProfile) {
                    // TODO try email before sub?
                    value = userProfile.username ?: userProfile.getAttribute(ATTR_USERID) ?: userProfile.getAttribute(ATTR_SUB)
                }
            }
        }
        return value
    }

    @Override
    String getDisplayName() {
        String displayName = getAttribute(ATTR_NAME)
        if (!displayName) {
            String firstname = getAttribute(ATTR_FIRST_NAME)
            String lastname = getAttribute(ATTR_LAST_NAME)
            if (firstname && lastname) {
                displayName = String.format("%s %s", firstname, lastname)
            } else if (firstname || lastname) {
                displayName = String.format("%s", firstname ?: lastname)
            }

        }
        return displayName
    }

    @Override
    String getFirstName() {
        return getAttribute(ATTR_FIRST_NAME) ?: getAttribute(ATTR_CAS_FIRST_NAME)
    }

    @Override
    String getLastName() {
        return getAttribute(ATTR_LAST_NAME) ?: getAttribute(ATTR_CAS_LAST_NAME)
    }

    /**
     *
     * @param request Needs to be a {@link org.pac4j.jee.util.Pac4JHttpServletRequestWrapper}
     * @return The users roles in a set or an empty set if the user is not authenticated
     */
    Set<String> getUserRoles() {
        def userProfile = userProfile

        if (userProfile != null) {
            Object roles = userProfile.attributes.get(ATTR_ROLES) ?: userProfile.attributes.get(ATTR_ROLE)
            if (roles instanceof Collection) {
                return new HashSet<String>((Collection)roles)
            } else if (roles instanceof String) {
                String rolesString = (String) roles
                Set<String> retVal = new HashSet<String>()
                if (rolesString) {
                    for (String role: rolesString.split(",")) {
                        retVal.add(role.trim())
                    }
                }
                return retVal;
            }
        }
        return Collections.emptySet()
    }

    @Override
    boolean userInRole(String role) {
        return userRoles.contains(role)
    }

    @Override
    UserDetails userDetails() {
        def attr = userProfile?.attributes
        def details = null

        if (attr) {
            details = new UserDetails(
                    userId: userId?.toString(),
                    userName: email?.toString()?.toLowerCase(),
                    firstName: firstName?.toString() ?: "",
                    lastName: lastName?.toString() ?: "",
                    locked: attr?.locked?.toBoolean() ?: false,
                    organisation: attr?.organisation?.toString() ?: "",
                    city: attr?.country?.toString() ?: "",
                    state: attr?.state?.toString() ?: "",
                    country: attr?.country?.toString() ?: "",
                    roles: userRoles
            )
        }

        details
    }

    @Override
    String loginUrl(String returnUrl) {
        return grailsLinkGenerator.link(mapping:'login', params: [path: returnUrl])
    }
}
