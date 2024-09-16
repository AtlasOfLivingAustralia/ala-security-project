package au.org.ala.pac4j.core.logout;

import au.org.ala.pac4j.core.CookieGenerator;
import org.pac4j.core.context.CallContext;
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
    public Optional<RedirectionAction> getLogoutAction(CallContext callContext, UserProfile userProfile, String targetUrl) {
        cookieGenerator.removeCookie(callContext.webContext());
        return delegate.getLogoutAction(callContext, userProfile, targetUrl);
    }
}
