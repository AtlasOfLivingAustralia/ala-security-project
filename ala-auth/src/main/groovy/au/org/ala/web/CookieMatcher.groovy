package au.org.ala.web

import org.pac4j.core.context.CallContext
import org.pac4j.core.matching.matcher.Matcher

class CookieMatcher implements Matcher {

    private final String cookieName
    private final String cookiePattern

    CookieMatcher(String cookieName, String cookiePattern) {
        this.cookiePattern = cookiePattern
        this.cookieName = cookieName
    }

    @Override
    boolean matches(CallContext ctx) {
        var context = ctx.webContext()
        return context.getRequestCookies().find { it.name == cookieName }?.value?.matches(cookiePattern) ?: false
    }
}
