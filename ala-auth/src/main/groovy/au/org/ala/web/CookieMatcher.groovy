package au.org.ala.web

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.matching.matcher.Matcher

class CookieMatcher implements Matcher {

    private final String cookieName
    private final String cookiePattern

    CookieMatcher(String cookieName, String cookiePattern) {
        this.cookiePattern = cookiePattern
        this.cookieName = cookieName
    }

    @Override
    boolean matches(WebContext context, SessionStore sessionStore) {
        return context.getRequestCookies().find { it.name == cookieName }?.value?.matches(cookiePattern) ?: false
    }
}
