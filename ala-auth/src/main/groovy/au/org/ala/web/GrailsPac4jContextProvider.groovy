package au.org.ala.web

import org.grails.web.util.WebUtils
import org.pac4j.core.adapter.FrameworkAdapter
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.jee.context.JEEFrameworkParameters

/**
 * Pac4jContextProvider that uses static Grails methods to get at the request and response.
 * // TODO This is probably not used, remove?
 */
class GrailsPac4jContextProvider implements Pac4jContextProvider {

    Config config

    GrailsPac4jContextProvider(Config config) {
        this.config = config
    }

    @Override
    WebContext webContext() {
        FrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config)
        def gwr = WebUtils.retrieveGrailsWebRequest()
        def request = gwr.request
        def response = gwr.response
        final WebContext context = config.getWebContextFactory().newContext(new JEEFrameworkParameters(request, response))
        return context
    }
}
