package au.org.ala.web

import org.grails.web.util.WebUtils
import org.pac4j.core.config.Config
import org.pac4j.core.context.JEEContextFactory
import org.pac4j.core.context.WebContext
import org.pac4j.core.util.FindBest

/**
 * Pac4jContextProvider that uses static Grails methods to get at the request and response.
 */
class GrailsPac4jContextProvider implements Pac4jContextProvider {

    Config config

    GrailsPac4jContextProvider(Config config) {
        this.config = config
    }

    @Override
    WebContext webContext() {
        def gwr = WebUtils.retrieveGrailsWebRequest()
        def request = gwr.request
        def response = gwr.response
        final WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)
        return context
    }
}
