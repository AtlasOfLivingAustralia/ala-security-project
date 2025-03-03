package au.org.ala.web

import org.pac4j.core.context.FrameworkParameters
import org.pac4j.core.context.WebContext

/**
 * Provides a Pac4j Context via static methods or similar so that the client code need not take them as params.
 *
 * @deprecated This interface is deprecated and will be removed in a future version.
 */
@Deprecated
interface Pac4jContextProvider {

    WebContext webContext()

    FrameworkParameters frameworkParameters()

}