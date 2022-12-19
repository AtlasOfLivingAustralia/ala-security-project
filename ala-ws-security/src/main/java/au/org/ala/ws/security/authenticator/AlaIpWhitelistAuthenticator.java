package au.org.ala.ws.security.authenticator;

import inet.ipaddr.IPAddressString;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.util.InitializableObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class AlaIpWhitelistAuthenticator extends InitializableObject implements Authenticator {
    private static final List<String> LOOPBACK_ADDRESSES = Arrays.asList("127.0.0.1",
                                                    "0:0:0:0:0:0:0:1",
                                                    "::1");

    private List<IPAddressString> ipMatches = LOOPBACK_ADDRESSES.stream().map(IPAddressString::new).collect(Collectors.toList());

    public void setIpWhitelist(Collection<String> ipWhitelist) {

        ArrayList<IPAddressString> result = new ArrayList<>(ipMatches.size() + ipWhitelist.size());
        result.addAll(ipMatches);
        ipWhitelist.forEach(s -> result.add(new IPAddressString(s)));
        ipMatches = result;
    }

    @Override
    public void validate(Credentials credentials, WebContext context, SessionStore sessionStore) {

        final IPAddressString ip = new IPAddressString(((TokenCredentials) credentials).getToken());

        if (ipMatches.stream().noneMatch(ipMatcher -> ipMatcher.contains(ip))) {
            throw new CredentialsException("Unauthorized IP address: " + ip);
        }
    }

    @Override
    protected void internalInit(boolean forceReinit) {

    }
}
