package au.org.ala.web

import groovy.transform.CompileStatic
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.engine.savedrequest.DefaultSavedRequestHandler

/**
 * SavedRequestHandler that allows the application to set the requested URL by adding a request attribute,
 * {@link OverrideSavedRequestHandler#OVERRIDE_REQUESTED_URL_ATTRIBUTE}, with the URL to redirect to.  If the
 * attribute is not set then this class falls back to the {@link DefaultSavedRequestHandler} behaviour.
 */
@CompileStatic
class OverrideSavedRequestHandler extends DefaultSavedRequestHandler {

    final static String OVERRIDE_REQUESTED_URL_ATTRIBUTE = '_ala_override_pac4j_requested_url_'

    protected String getRequestedUrl(final WebContext context, final SessionStore sessionStore) {
        return context.getRequestAttribute(OVERRIDE_REQUESTED_URL_ATTRIBUTE).orElseGet { super.getRequestedUrl(context, sessionStore) }
    }
}
