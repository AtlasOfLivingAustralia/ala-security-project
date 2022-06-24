package au.org.ala.web

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.logout.handler.LogoutHandler
import org.pac4j.core.profile.factory.ProfileManagerFactoryAware
import org.pac4j.core.util.CommonHelper
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.session.FindByIndexNameSessionRepository
import org.springframework.session.Session

/**
 * This is a LogoutHandler that works with the Spring Session repository instead of relying
 * on a Pac4J Store as the DefaultLogoutHandler does.  The behaviour should be equivalent to that
 * of the DefaultLogoutHandler.
 *
 * It stores the OIDC Session ID (SID) in the Spring Session PRINCIPAL_NAME_INDEX_NAME attribute,
 * so that it can then lookup sessions based on the SID for Single Logout.
 */
class SpringSessionLogoutHandler extends ProfileManagerFactoryAware implements LogoutHandler {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private boolean destroySession;
    private FindByIndexNameSessionRepository<Session> repository

    SpringSessionLogoutHandler(FindByIndexNameSessionRepository<Session> repository) {
        this.repository = repository
    }


    @Override
    void recordSession(final WebContext context, final SessionStore sessionStore, final String key) {
        if (sessionStore == null) {
            logger.error("No session store available for this web context");
        } else {
            sessionStore.set(context, FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, key)
        }
    }

    @Override
    void destroySessionFront(final WebContext context, final SessionStore sessionStore, final String key) {
        def sessions
        if (!key) {
            def sessionId = sessionStore.getSessionId(context, false).orElse('')
            if (sessionId) {
                sessions = [(sessionId): repository.findById(sessionId)]
            } else {
                sessions = [:]
            }
        } else {
            sessions = repository.findByPrincipalName(key)
        }

        sessions.keySet().each { id -> repository.deleteById(id) }

        destroy(context, sessionStore, "front")

    }

    protected void destroy(final WebContext context, final SessionStore sessionStore, final String channel) {
        // remove profiles
        final def manager = getProfileManager(context, sessionStore);
        manager.removeProfiles();
        logger.debug("{} channel logout call: destroy the user profiles", channel);
        // and optionally the web session
        if (destroySession) {
            logger.debug("destroy the whole session");
            final def invalidated = sessionStore.destroySession(context);
            if (!invalidated) {
                logger.error("The session has not been invalidated");
            }
        }
    }

    @Override
    void destroySessionBack(final WebContext context, final SessionStore sessionStore, final String key) {
        def sessions
        if (!key) {
            sessions = [:]
        } else {
            sessions = repository.findByPrincipalName(key)
        }

        sessions.keySet().each { id -> repository.deleteById(id) }

        destroy(context, sessionStore, "back")

    }

    @Override
    void renewSession(final String oldSessionId, final WebContext context, final SessionStore sessionStore) {
        def oldSession = repository.findById(oldSessionId)
        def key = oldSession?.getAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME)
        if (key) {
            repository.deleteById(oldSessionId)
            recordSession(context, sessionStore, key)
        }
    }

    boolean isDestroySession() {
        return destroySession;
    }

    void setDestroySession(final boolean destroySession) {
        this.destroySession = destroySession;
    }

    @Override
    String toString() {
        return CommonHelper.toNiceString(this.getClass(), "repository", repository, "destroySession", destroySession)
    }
}
