package au.org.ala.web

import org.pac4j.core.context.WebContext

/**
 * Provides a Pac4j Context via static methods or similar so that the client code need not take them as params.
 */
interface Pac4jContextProvider {

    WebContext webContext()
}