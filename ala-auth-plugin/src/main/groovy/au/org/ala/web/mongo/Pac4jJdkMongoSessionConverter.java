package au.org.ala.web.mongo;

import com.mongodb.DBObject;
import org.pac4j.core.profile.AnonymousProfile;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.Pac4jConstants;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.mongodb.core.index.IndexOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.lang.Nullable;
import org.springframework.session.Session;
import org.springframework.session.data.mongo.JdkMongoSessionConverter;
import org.springframework.session.data.mongo.MongoSession;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static au.org.ala.web.SpringSessionLogoutHandler.SID_INDEX_NAME;
import static au.org.ala.web.SpringSessionLogoutHandler.SID_FIELD_NAME;

/**
 * Copy of the Spring Session JDK Mongo Session Converter with an additional field for specifying an external
 * Session ID.
 *
 * It additionally extracts the principal name from the Pac4j profile name if available
 */
public class Pac4jJdkMongoSessionConverter extends JdkMongoSessionConverter {

    public Pac4jJdkMongoSessionConverter(Duration maxInactiveInterval) {
        super(maxInactiveInterval);
    }

    public Pac4jJdkMongoSessionConverter(Converter<Object, byte[]> serializer, Converter<byte[], Object> deserializer, Duration maxInactiveInterval) {
        super(serializer, deserializer, maxInactiveInterval);
    }

    protected void ensureIndexes(IndexOperations sessionCollectionIndexes) {
        super.ensureIndexes(sessionCollectionIndexes);
        // TODO SID mongo index?
    }

    @Override
    @Nullable
    public Query getQueryForIndex(String indexName, Object indexValue) {

        if (SID_INDEX_NAME.equals(indexName)) {
            return Query.query(Criteria.where(SID_FIELD_NAME).is(indexValue));
        } else {
            return super.getQueryForIndex(indexName, indexValue);
        }
    }

    @Override
    protected DBObject convert(MongoSession session) {

        DBObject basicDBObject = super.convert(session);

        basicDBObject.put(SID_FIELD_NAME, extractSessionId(session));

        return basicDBObject;
    }

    protected String extractSessionId(MongoSession session) {
        return getProfile(session).map(profile -> (String) profile.getAttribute(Pac4jConstants.OIDC_CLAIM_SESSIONID)).orElse(null);
    }

    @Override
    protected String extractPrincipal(Session session) {
        return getProfile(session).map(profile -> profile.getUsername()).orElseGet(() -> super.extractPrincipal(session));
    }

    private Optional<UserProfile> getProfile(Session session) {
        // Could use profile manager here but that requires the request and response...
        var result = Optional.<UserProfile>empty();
        if (session.getAttributeNames().contains(Pac4jConstants.USER_PROFILES)) {
            var profiles = session.getAttribute(Pac4jConstants.USER_PROFILES);
            if (profiles instanceof Map) {
                var profile = ((Map<String, UserProfile>) profiles).values()
                        .stream()
                        .filter(p -> p != null && !(p instanceof AnonymousProfile))
                        .filter( p -> !p.isExpired() )
                        .findFirst();
                if (profile.isPresent()) {
                    result = profile;
                } else {
                    result = ((Map<String, UserProfile>) profiles).values().stream().filter(Objects::nonNull).findFirst();
                }

            }
        }
        return result;
    }
}
