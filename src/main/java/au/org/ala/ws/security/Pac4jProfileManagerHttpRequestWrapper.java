package au.org.ala.ws.security;

import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Optional;

/**
 * Use the Pac4j profile manager to get the request principal, so that a JWT can be inserted into a profile manager
 * and the resulting profile can feed into isUserInRole, getRemoteUser and so on.
 */
public class Pac4jProfileManagerHttpRequestWrapper extends HttpServletRequestWrapper {

    private final ProfileManager profileManager;

    public Pac4jProfileManagerHttpRequestWrapper(HttpServletRequest request, ProfileManager profileManager) {
        super(request);

        this.profileManager = profileManager;
    }

    @Override
    public String getRemoteUser() {
        return getPrincipal().map(Principal::getName).orElseGet(super::getRemoteUser);
    }

    private Optional<Principal> getPrincipal() {
        return profileManager.getProfile().map(UserProfile::asPrincipal);
    }

    @Override
    public Principal getUserPrincipal() {
        return getPrincipal().orElseGet(super::getUserPrincipal);
    }

    @Override
    public boolean isUserInRole(String role) {
        return profileManager.getProfiles().stream().anyMatch(p -> p.getRoles().contains(role)) || super.isUserInRole(role);
    }
}
