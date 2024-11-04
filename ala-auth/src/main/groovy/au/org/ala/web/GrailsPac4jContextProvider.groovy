package au.org.ala.web

import org.grails.web.util.WebUtils
import org.pac4j.core.adapter.FrameworkAdapter
import org.pac4j.core.config.Config
import org.pac4j.core.context.FrameworkParameters
import org.pac4j.core.context.WebContext
import org.pac4j.jee.context.JEEFrameworkParameters

/**
 * Pac4jContextProvider that uses static Grails methods to get at the request and response.
 * @deprecated This interface is deprecated and will be removed in a future version.
 */
@Deprecated
class GrailsPac4jContextProvider implements Pac4jContextProvider {

    Config config

    GrailsPac4jContextProvider(Config config) {
        this.config = config
    }

    @Override
    WebContext webContext() {
        final WebContext context = config.getWebContextFactory().newContext(frameworkParameters())
        return context
    }

    FrameworkParameters frameworkParameters() {
        FrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config)
        def gwr = WebUtils.retrieveGrailsWebRequest()
        def request = gwr.request
        def response = gwr.response
        return new JEEFrameworkParameters(request, response)
    }
}
