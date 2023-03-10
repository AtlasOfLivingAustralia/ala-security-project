package au.org.ala.web

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.matching.matcher.Matcher

/**
 * PAC4j matcher that uses the User-Agent header to determine if the client is a search bot.
 */
class NotBotMatcher implements Matcher {

    private UserAgentFilterService filterService

    NotBotMatcher(UserAgentFilterService filterService) {

        this.filterService = filterService
    }

    @Override
    boolean matches(WebContext context, SessionStore sessionStore) {
        def headerValue = context.getRequestHeader("User-Agent")
        def header = headerValue.orElseGet { "" }
        return !filterService.isFiltered(header)
    }
}
