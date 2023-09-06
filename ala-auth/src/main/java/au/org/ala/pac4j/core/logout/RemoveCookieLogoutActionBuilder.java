package au.org.ala.pac4j.core.logout;

import au.org.ala.pac4j.core.CookieGenerator;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.core.logout.LogoutActionBuilder;
import org.pac4j.core.profile.UserProfile;

import java.util.Optional;

/**
 * Removes the ALA Auth Cookie and then delegates to another logout action builder
 */
public class RemoveCookieLogoutActionBuilder implements LogoutActionBuilder {

    private LogoutActionBuilder delegate;
    private CookieGenerator cookieGenerator;

    public RemoveCookieLogoutActionBuilder(LogoutActionBuilder delegate, CookieGenerator cookieGenerator) {
        this.delegate = delegate;
        this.cookieGenerator = cookieGenerator;
    }

    @Override
    public Optional<RedirectionAction> getLogoutAction(WebContext context, SessionStore sessionStore, UserProfile currentProfile, String targetUrl) {
        cookieGenerator.removeCookie(context);
        return delegate.getLogoutAction(context, sessionStore, currentProfile, targetUrl);
    }
}
