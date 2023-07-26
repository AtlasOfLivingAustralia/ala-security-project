package au.org.ala.web.pac4j

import au.org.ala.pac4j.core.CookieGenerator
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.DefaultCallbackLogic
import org.pac4j.core.exception.http.HttpAction

class AlaCookieCallbackLogic extends DefaultCallbackLogic {

    CookieGenerator cookieGenerator

    AlaCookieCallbackLogic(CookieGenerator cookieGenerator) {
        this.cookieGenerator = cookieGenerator
    }

    @Override
    protected HttpAction redirectToOriginallyRequestedUrl(WebContext context, SessionStore sessionStore, String defaultUrl) {
        getProfileManager(context, sessionStore).getProfile().ifPresent { profile ->
            // TODO Do we actually need to put the username in the cookie value?
            this.cookieGenerator.addCookie(context, profile.username ?: profile.id ?: profile.typedId)
        }
        return super.redirectToOriginallyRequestedUrl(context, sessionStore, defaultUrl)
    }
}
