package au.org.ala.ws.security.authenticator

import inet.ipaddr.IPAddressString
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.credentials.authenticator.Authenticator
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.util.InitializableObject

class AlaIpWhitelistAuthenticator extends InitializableObject implements Authenticator {

    static final List<String> LOOPBACK_ADDRESSES = ["127.0.0.1",
                                                    "0:0:0:0:0:0:0:1", // IP v6
                                                    "::1"]

    private List<IPAddressString> ipMatches = LOOPBACK_ADDRESSES.collect { new IPAddressString(it) }

    void setIpWhitelist(Collection<String> ipWhitelist) {

        ipMatches += ipWhitelist.collect { String ipAddress ->
            new IPAddressString(ipAddress)
        }
    }

    @Override
    void validate(Credentials credentials, WebContext context, SessionStore sessionStore) {

        final IPAddressString ip = new IPAddressString(((TokenCredentials) credentials).getToken())

        if (!ipMatches.any { IPAddressString ipMatcher -> ipMatcher.contains(ip) }) {
            throw new CredentialsException("Unauthorized IP address: " + ip)
        }
    }

    @Override
    protected void internalInit(boolean forceReinit) {

    }
}
