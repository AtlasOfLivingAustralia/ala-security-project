package au.org.ala.ws.security.credentials

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.credentials.extractor.CredentialsExtractor
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

@Component
@ConditionalOnProperty('security.ip.whitelist')
class AlaIpExtractor implements CredentialsExtractor {

    static final List<String> LOOPBACK_ADDRESSES = ["127.0.0.1",
                                                    "0:0:0:0:0:0:0:1", // IP v6
                                                    "::1"]

    @Override
    Optional<Credentials> extract(WebContext context, SessionStore sessionStore) {

        // External requests may be proxied by Apache, which uses X-Forwarded-For to identify the original IP.
        Optional<String> ip = context.getRequestHeader("X-Forwarded-For")
        if (!ip.present || LOOPBACK_ADDRESSES.contains(ip.get())) {
            // don't accept localhost from the X-Forwarded-For header, since it can be easily spoofed.
            ip = Optional.of(context.getRemoteAddr())
        }

        return ip.map { String ipAddress ->
            new TokenCredentials(ipAddress)
        }
    }

}
