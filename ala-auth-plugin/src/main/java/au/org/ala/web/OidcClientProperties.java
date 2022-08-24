package au.org.ala.web;

import org.pac4j.core.context.HttpConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

@ConfigurationProperties(value = "security.oidc")
public class OidcClientProperties {

    private boolean enabled = false;
    private String discoveryUri = "https://auth.ala.org.au/cas/oidc/.well-known";
    private String clientId = "ChangeMe";
    private String secret = "ChangeMe";
    private String scope = "openid profile email roles";
    private boolean withState = true;
    private Map<String,String> customParams = new LinkedHashMap<>();
    private String clientAuthenticationMethod = null;
    private boolean allowUnsignedIdTokens = false;
    private boolean useAnonymousClient = true;
    private int connectTimeout = HttpConstants.DEFAULT_CONNECT_TIMEOUT;
    private int readTimeout = HttpConstants.DEFAULT_READ_TIMEOUT;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getDiscoveryUri() {
        return discoveryUri;
    }

    public void setDiscoveryUri(String discoveryUri) {
        this.discoveryUri = discoveryUri;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public boolean isWithState() {
        return withState;
    }

    public void setWithState(boolean withState) {
        this.withState = withState;
    }

    public Map<String, String> getCustomParams() {
        return customParams;
    }

    public void setCustomParams(Map<String, String> customParams) {
        this.customParams = customParams;
    }

    public String getClientAuthenticationMethod() {
        return clientAuthenticationMethod;
    }

    public void setClientAuthenticationMethod(String clientAuthenticationMethod) {
        this.clientAuthenticationMethod = clientAuthenticationMethod;
    }

    public boolean isAllowUnsignedIdTokens() {
        return allowUnsignedIdTokens;
    }

    public void setAllowUnsignedIdTokens(boolean allowUnsignedIdTokens) {
        this.allowUnsignedIdTokens = allowUnsignedIdTokens;
    }

    public boolean isUseAnonymousClient() {
        return useAnonymousClient;
    }

    public void setUseAnonymousClient(boolean useAnonymousClient) {
        this.useAnonymousClient = useAnonymousClient;
    }

    public int getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
    }
}
