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
public class GrailsPac4jHttpRequestWrapper extends HttpServletRequestWrapper {

    private final ProfileManager profileManager;

    public GrailsPac4jHttpRequestWrapper(HttpServletRequest request, HttpServletResponse response, SessionStore sessionStore) {
        super(request);

        this.profileManager = new ProfileManager(new JEEContext(this, response), sessionStore);
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
