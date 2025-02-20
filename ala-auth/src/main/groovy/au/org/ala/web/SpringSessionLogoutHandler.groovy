package au.org.ala.web

import au.org.ala.web.pac4j.EmptySessionStore
import au.org.ala.web.springsession.SpringSessionStore
import org.pac4j.core.context.CallContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.logout.handler.SessionLogoutHandler
import org.pac4j.core.profile.factory.ProfileManagerFactory
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
 * It stores the OIDC Session ID (SID) in the Spring Session SID_FIELD_NAME attribute,
 * so that it can then lookup sessions based on the SID for Single Logout.
 *
 * {@link org.springframework.session.data.mongo.AbstractMongoSessionConverter}
 * instances need to accept {@link #SID_INDEX_NAME} as the index name for looking up the
 * {@link #SID_FIELD_NAME} value.  One such implementation is provided in this plugin:
 * {@link au.org.ala.web.mongo.Pac4jJdkMongoSessionConverter}
 */
class SpringSessionLogoutHandler implements SessionLogoutHandler {

    protected final Logger logger = LoggerFactory.getLogger(getClass())

    private FindByIndexNameSessionRepository<Session> repository

    public static final String SID_INDEX_NAME = FindByIndexNameSessionRepository.class.getName()
            .concat(".SID_INDEX_NAME")
    public static final String SID_FIELD_NAME = "_sid"

    SpringSessionLogoutHandler(FindByIndexNameSessionRepository<Session> repository) {
        this.repository = repository
    }


    @Override
    void recordSession(final CallContext ctx, final String key) {
        var webContext = ctx.webContext()
        var sessionStore = ctx.sessionStore()

        if (sessionStore == null) {
            logger.error("No session store available for this web context")
        } else {
            // unnecessary? JDK Converter should extract into serialised session
             sessionStore.set(webContext, SID_FIELD_NAME, key)
        }
    }

    @Override
    public void destroySession(final CallContext ctx, final String key) {
        var webContext = ctx.webContext()
        var sessionStore = ctx.sessionStore()

        def optCurrentSessionId = sessionStore.getSessionId(webContext, false)
        if (optCurrentSessionId.isPresent()) {
            var currentSessionId = optCurrentSessionId.get()
            logger.debug("current sessionId: {}", currentSessionId)

//            var keyForCurrentSession = (String) store.get(currentSessionId).orElse(null);
            var keyForCurrentSession = repository.findById(currentSessionId)
            logger.debug("key associated to the current session: {}", keyForCurrentSession.getId())
            repository.deleteById(currentSessionId)
            //            store.remove(currentSessionId);

//            if (CommonHelper.areEquals(key, keyForCurrentSession.getId())) {
            // currentSessionId is always keyForCurrentSession.getId() as this stage
                destroy(webContext, sessionStore, ctx.profileManagerFactory(), "front");
                return;
//            } else {
//                logger.debug("Unknown/new web session: cannot perform front channel logout");
//            }

        } else {
            logger.debug("No web session: cannot perform front channel logout");

        }

        // moved from start of method as we don't want to delete the current session before running
        // the front channel logout logic
        //         var optTrackableSession = store.get(key);
        //        if (optTrackableSession.isPresent()) {
        //            store.remove(key);
        //        }

        var sessionsForKey = repository.findByIndexNameAndIndexValue(SID_INDEX_NAME, key)

        logger.debug("TrackableSession: {} for key: {}", sessionsForKey, key);
        if (sessionsForKey.isEmpty()) {
            logger.debug("No trackable session: cannot perform back channel logout");
        } else {

//            var optNewSessionStore = sessionStore
//                    .buildFromTrackableSession(webContext, optTrackableSession.get());
//            if (optNewSessionStore.isPresent()) {
//                var newSessionStore = optNewSessionStore.get();
//                logger.debug("newSesionStore: {}", newSessionStore);
//                var sessionId = newSessionStore.getSessionId(webContext, true).get();
//                logger.debug("new sessionId: {}", sessionId);
//                store.remove(sessionId);

            // create a dummy session store to pass to the profile manager.  Since we've already
            // destroyed the session in the session repository, there's no need for the profile
            // manager to remove profiles from the session
            var dummySessionStore = new EmptySessionStore()

            sessionsForKey.each { id, session ->
                repository.deleteById(id)
                destroy(webContext, dummySessionStore, ctx.profileManagerFactory(), "back");
            }

            return;
//            } else {
//                logger.warn("Cannot build new session store from tracked session: cannot perform back channel logout");
//            }
        }


    }

//    @Override
//    void destroySessionFront(final CallContext ctx, final String key) {
//        var webContext = ctx.webContext()
//        var sessionStore = ctx.sessionStore()
//
//        def sessions
//        if (!key) {
//            def sessionId = sessionStore.getSessionId(webContext, false).orElse('')
//            if (sessionId) {
//                sessions = [(sessionId): repository.findById(sessionId)]
//            } else {
//                sessions = [:]
//            }
//        } else {
//            sessions = repository.findByIndexNameAndIndexValue(SID_INDEX_NAME, key)
//        }
//
//        sessions.keySet().each { id -> repository.deleteById(id) }
//
//        destroy(ctx, "front")
//
//    }

    protected void destroy(final WebContext webContext, final SessionStore sessionStore,
                           final ProfileManagerFactory profileManagerFactory, final String channel) {

        // remove profiles
        final def manager = profileManagerFactory.apply(webContext, sessionStore);
        manager.removeProfiles();
        logger.debug("{} channel logout call: destroy the user profiles", channel);
        // and optionally the web session
        // This is already done via the Spring Session repository
//        if (destroySession) {
//            logger.debug("destroy the whole session");
//            final def invalidated = sessionStore.destroySession(webContext);
//            if (!invalidated) {
//                logger.error("The session has not been invalidated");
//            }
//        }
    }

//    @Override
//    void destroySessionBack(final CallContext ctx, final String key) {
//        var webContext = ctx.webContext()
//        var sessionStore = ctx.sessionStore()
//
//        def sessions
//        if (!key) {
//            sessions = [:]
//        } else {
//            sessions = repository.findByIndexNameAndIndexValue(SID_INDEX_NAME, key)
//        }
//
//        sessions.keySet().each { id -> repository.deleteById(id) }
//
//        destroy(ctx, "back")
//
//    }

    @Override
    void renewSession(final CallContext ctx, final String oldSessionId) {
        var webContext = ctx.webContext()
        var sessionStore = ctx.sessionStore()

        def oldSession = repository.findById(oldSessionId)
        def key = oldSession?.getAttribute(SID_FIELD_NAME)
        if (key) {
            repository.deleteById(oldSessionId)
            recordSession(webContext, sessionStore, key)
        }
    }

    @Override
    Optional<String> cleanRecord(String sessionId) {
        // todo test renewSession?
//        val key = (String) store.get(sessionId).orElse(null);
        def session = repository.findById(sessionId)
//        store.remove(sessionId);
        def key = (String) session?.getAttribute(SID_FIELD_NAME)
        session?.removeAttribute(SID_FIELD_NAME)
        logger.debug("cleaning sessionId: {} -> key: {}", sessionId, key);

        return Optional.ofNullable(key)
    }

    boolean isDestroySession() {
        return true;
    }

    void setDestroySession(final boolean destroySession) {
        if (!destroySession) {
            logger.error("Attempt to set destroySession to false but SpringSessionLogoutHandler always destroys the session");
        }
    }

    @Override
    String toString() {
        return CommonHelper.toNiceString(this.getClass(), "repository", repository)
    }
}
