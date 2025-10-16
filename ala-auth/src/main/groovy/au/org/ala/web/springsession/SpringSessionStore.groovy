package au.org.ala.web.springsession

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.springframework.session.Session
import org.springframework.session.SessionRepository

class SpringSessionStore<S extends Session> implements SessionStore {

    private final S session
    private SessionRepository<S> sessionRepository;

    SpringSessionStore(S session, SessionRepository<S> sessionRepository) {
        this.session = session
        this.sessionRepository = sessionRepository
    }

    @Override
    Optional<String> getSessionId(WebContext context, boolean createSession) {
        return Optional.of(session.getId())
    }

    @Override
    Optional<Object> get(WebContext context, String key) {
        return Optional.ofNullable(session.getAttribute(key))
    }

    @Override
    void set(WebContext context, String key, Object value) {
        session.setAttribute(key, value)
    }

    @Override
    boolean destroySession(WebContext context) {
        return sessionRepository.deleteById(session.getId())
    }

    @Override
    Optional<Object> getTrackableSession(WebContext context) {
        return session
    }

    @Override
    Optional<SessionStore> buildFromTrackableSession(WebContext context, Object trackableSession) {
        return Optional.of(new SpringSessionStore(session, sessionRepository))
    }

    @Override
    boolean renewSession(WebContext context) {
        return session.changeSessionId()
    }
}
