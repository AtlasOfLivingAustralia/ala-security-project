package au.org.ala.web;

import org.pac4j.core.context.HttpConstants;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.OidcProfileDefinition;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
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

    /**
     * Only set this if the OIDC provider doesn't set the end_session_url in the discovery document
     */
    private String logoutUrl = null;

    /**
     * Only set this if the standard OIDC logout is not supported.
     */
    private LogoutActionType logoutAction = LogoutActionType.DEFAULT;

    /**
     * A prefix to add to all incoming role names, e.g. cognito which might provide role names like "user" but
     * the application code requires the role name to be "role_user"
     */
    private String rolePrefix = "";

    /**
     * Whether to convert all incoming role names to upper case, e.g. cognito which might provide role names like
     * "user" but the application code requires the role name to be "USER"
     */
    private boolean convertRolesToUpperCase = true;

    /**
     * Set this to add a preferred claim name to retrieve the ala user id from
     */
    private String alaUseridClaim = null;

    /**
     * Set this to add a preferred claim name to retrieve the user name from
     */
    private String userNameClaim = null;

    /**
     * Set this to the claim name that contains the full display name for the user,
     * set to null to calculate from first and last names.
     */
    private String displayNameClaim = OidcProfileDefinition.NAME;
    private int maxClockSkew = OidcConfiguration.DEFAULT_MAX_CLOCK_SKEW;
    /**
     * Maximum number of times to retry internal OIDC HTTP calls.
     */
    private int maximumRetries = 10;
    /**
     * Initial delay before retrying an internal OIDC HTTP call.
     */
    private Duration initialRetryInterval = Duration.ofSeconds(1);
    /**
     * Maximum interval between internal OIDC HTTP calls.
     *
     * Retry interval will exponentially increase from the initial interval up to this value.
     */
    private Duration maximumRetryInterval = Duration.ofSeconds(30);

    private boolean cacheLastDiscoveryDocument = false;
    private String discoveryDocumentCache =  "/tmp/oidc-discovery-doc.json";

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

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public LogoutActionType getLogoutAction() {
        return logoutAction;
    }

    public void setLogoutAction(LogoutActionType logoutAction) {
        this.logoutAction = logoutAction;
    }

    public String getRolePrefix() {
        return rolePrefix;
    }

    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    public boolean isConvertRolesToUpperCase() {
        return convertRolesToUpperCase;
    }

    public void setConvertRolesToUpperCase(boolean convertRolesToUpperCase) {
        this.convertRolesToUpperCase = convertRolesToUpperCase;
    }

    public String getAlaUseridClaim() {
        return alaUseridClaim;
    }

    public void setAlaUseridClaim(String alaUseridClaim) {
        this.alaUseridClaim = alaUseridClaim;
    }

    public String getUserNameClaim() {
        return userNameClaim;
    }

    public void setUserNameClaim(String userNameClaim) {
        this.userNameClaim = userNameClaim;
    }

    public String getDisplayNameClaim() {
        return displayNameClaim;
    }

    public void setDisplayNameClaim(String displayNameClaim) {
        this.displayNameClaim = displayNameClaim;
    }

    public int getMaxClockSkew() {
        return maxClockSkew;
    }

    public void setMaxClockSkew(int maxClockSkew) {
        this.maxClockSkew = maxClockSkew;
    }

    public int getMaximumRetries() {
        return maximumRetries;
    }

    public void setMaximumRetries(int maximumRetries) {
        this.maximumRetries = maximumRetries;
    }

    public Duration getInitialRetryInterval() {
        return initialRetryInterval;
    }

    public void setInitialRetryInterval(Duration initialRetryInterval) {
        this.initialRetryInterval = initialRetryInterval;
    }

    public Duration getMaximumRetryInterval() {
        return maximumRetryInterval;
    }

    public void setMaximumRetryInterval(Duration maximumRetryInterval) {
        this.maximumRetryInterval = maximumRetryInterval;
    }

    public boolean isCacheLastDiscoveryDocument() {
        return cacheLastDiscoveryDocument;
    }

    public void setCacheLastDiscoveryDocument(boolean cacheLastDiscoveryDocument) {
        this.cacheLastDiscoveryDocument = cacheLastDiscoveryDocument;
    }

    public String getDiscoveryDocumentCache() {
        return discoveryDocumentCache;
    }

    public void setDiscoveryDocumentCache(String discoveryDocumentCache) {
        this.discoveryDocumentCache = discoveryDocumentCache;
    }
}
