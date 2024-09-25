package au.org.ala.web.pac4j

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore

class EmptySessionStore implements SessionStore {

    @Override
    Optional<String> getSessionId(WebContext context, boolean createSession) {
        return Optional.empty()
    }

    @Override
    Optional<Object> get(WebContext context, String key) {
        return Optional.empty()
    }

    @Override
    void set(WebContext context, String key, Object value) {

    }

    @Override
    boolean destroySession(WebContext context) {
        return false
    }

    @Override
    Optional<Object> getTrackableSession(WebContext context) {
        return Optional.empty()
    }

    @Override
    Optional<SessionStore> buildFromTrackableSession(WebContext context, Object trackableSession) {
        return Optional.empty()
    }

    @Override
    boolean renewSession(WebContext context) {
        return false
    }

}
