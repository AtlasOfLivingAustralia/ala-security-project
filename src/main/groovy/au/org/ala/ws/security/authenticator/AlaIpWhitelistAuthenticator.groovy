package au.org.ala.ws.security.authenticator

import au.org.ala.ws.security.credentials.AlaIpExtractor
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.credentials.authenticator.Authenticator
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.util.InitializableObject
import org.springframework.security.web.util.matcher.IpAddressMatcher

class AlaIpWhitelistAuthenticator extends InitializableObject implements Authenticator {

    private List<IpAddressMatcher> ipMatches = AlaIpExtractor.LOOPBACK_ADDRESSES.collect { new IpAddressMatcher(it) }

    void setIpWhitelist(Collection<String> ipWhitelist) {

        ipMatches += ipWhitelist.collect { String ipAddress ->
            new IpAddressMatcher(ipAddress)
        }
    }

    @Override
    void validate(Credentials credentials, WebContext context, SessionStore sessionStore) {

        final String ip = ((TokenCredentials) credentials).getToken()

        if (!ipMatches.any { IpAddressMatcher ipMatcher -> ipMatcher.matches(ip) }) {
            throw new CredentialsException("Unauthorized IP address: " + ip)
        }
    }

    @Override
    protected void internalInit(boolean forceReinit) {

    }
}
