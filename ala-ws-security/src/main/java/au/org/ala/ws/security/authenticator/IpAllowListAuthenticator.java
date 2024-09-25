package au.org.ala.ws.security.authenticator;

import inet.ipaddr.IPAddressString;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.TokenCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.profile.definition.CommonProfileDefinition;
import org.pac4j.core.profile.definition.ProfileDefinitionAware;
import org.pac4j.http.profile.IpProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class IpAllowListAuthenticator extends ProfileDefinitionAware implements Authenticator {

    private static final Logger logger = LoggerFactory.getLogger(IpAllowListAuthenticator.class);

    private static final List<String> LOOPBACK_ADDRESSES = Arrays.asList("127.0.0.1",
                                                    "0:0:0:0:0:0:0:1",
                                                    "::1");

    private List<IPAddressString> ipMatches = LOOPBACK_ADDRESSES.stream().map(IPAddressString::new).collect(Collectors.toList());

    public IpAllowListAuthenticator() {
    }

    public IpAllowListAuthenticator(Collection<String> ipAllowList) {
        setIpAllowList(ipAllowList);
    }

    public void setIpAllowList(Collection<String> ipAllowList) {

        ArrayList<IPAddressString> result = new ArrayList<>(ipMatches.size() + ipAllowList.size());
        result.addAll(ipMatches);
        ipAllowList.forEach(s -> result.add(new IPAddressString(s)));
        ipMatches = result;
    }

    @Override
    public Optional<Credentials> validate(CallContext callContext, Credentials credentials) {

        init();

        String ipString = ((TokenCredentials) credentials).getToken();
        final IPAddressString ip = new IPAddressString(ipString);

        if (ipMatches.stream().noneMatch(ipMatcher -> ipMatcher.contains(ip))) {
            throw new CredentialsException("Unauthorized IP address: " + ip);
        }

        UserProfile profile = (IpProfile) getProfileDefinition().newProfile();
        profile.setId(ipString);
        logger.debug("profile: {}", profile);

        credentials.setUserProfile(profile);

        return Optional.of(credentials);
    }

    @Override
    protected void internalInit(boolean forceReinit) {
        setProfileDefinitionIfUndefined(new CommonProfileDefinition(x -> new IpProfile()));
    }
}
