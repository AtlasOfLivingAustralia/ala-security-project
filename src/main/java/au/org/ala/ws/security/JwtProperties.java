package au.org.ala.ws.security;

import org.pac4j.core.context.HttpConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(value = "security.jwt")
public class JwtProperties {
    private boolean enabled = true;
    private boolean fallbackToLegacyBehaviour = true; // Whether to check API keys if no JWT token is present on the request.
    private String clientId; // TODO Not used
    private String secret; // TODO Not used
    private String discoveryUri;
    private String jwtType = "jwt";
    private int connectTimeoutMs = HttpConstants.DEFAULT_CONNECT_TIMEOUT;;
    private int readTimeoutMs = HttpConstants.DEFAULT_READ_TIMEOUT;
    private List<String> roleAttributes = List.of("role");
    private List<String> permissionAttributes = List.of("scope","scp");
    private List<String> requiredClaims = List.of("sub", "iat", "exp", "nbf", "cid", "jti");
    private List<String> requiredScopes = List.of();
    private List<String> urlPatterns = List.of(); // hard coded paths to apply JWT authentication to

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

    public String getDiscoveryUri() {
        return discoveryUri;
    }

    public void setDiscoveryUri(String discoveryUri) {
        this.discoveryUri = discoveryUri;
    }

    public int getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public void setConnectTimeoutMs(int connectTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
    }

    public int getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public void setReadTimeoutMs(int readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isFallbackToLegacyBehaviour() {
        return fallbackToLegacyBehaviour;
    }

    public void setFallbackToLegacyBehaviour(boolean fallbackToLegacyBehaviour) {
        this.fallbackToLegacyBehaviour = fallbackToLegacyBehaviour;
    }

    public String getJwtType() {
        return jwtType;
    }

    public void setJwtType(String jwtType) {
        this.jwtType = jwtType;
    }

    public List<String> getRoleAttributes() {
        return roleAttributes;
    }

    public void setRoleAttributes(List<String> roleAttributes) {
        this.roleAttributes = roleAttributes;
    }

    public List<String> getPermissionAttributes() {
        return permissionAttributes;
    }

    public void setPermissionAttributes(List<String> permissionAttributes) {
        this.permissionAttributes = permissionAttributes;
    }

    public List<String> getRequiredClaims() {
        return requiredClaims;
    }

    public void setRequiredClaims(List<String> requiredClaims) {
        this.requiredClaims = requiredClaims;
    }

    public List<String> getRequiredScopes() {
        return requiredScopes;
    }

    public void setRequiredScopes(List<String> requiredScopes) {
        this.requiredScopes = requiredScopes;
    }

    public List<String> getUrlPatterns() {
        return urlPatterns;
    }

    public void setUrlPatterns(List<String> urlPatterns) {
        this.urlPatterns = urlPatterns;
    }
}
