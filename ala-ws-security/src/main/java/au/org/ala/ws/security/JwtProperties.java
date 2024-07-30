package au.org.ala.ws.security;

import org.pac4j.core.context.HttpConstants;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Set;

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

    private boolean rolesFromAccessToken = true;
    private String rolePrefix = "ROLE_";
    private boolean roleToUppercase = true;
    private List<String> roleClaims = List.of("role");
    private List<String> permissionClaims = List.of("scope","scp", "scopes");

    private String userIdClaim = "userid";
    private List<String> requiredClaims = List.of("sub", "iat", "exp", "client_id", "jti", "iss");
    private List<String> prohibitedClaims = List.of();
    private List<String> requiredScopes = List.of();
    private List<String> urlPatterns = List.of(); // hard coded paths to apply JWT authentication to

    private Set<String> acceptedAudiences = Set.of();

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

    public boolean isRolesFromAccessToken() {
        return rolesFromAccessToken;
    }

    public void setRolesFromAccessToken(boolean rolesFromAccessToken) {
        this.rolesFromAccessToken = rolesFromAccessToken;
    }

    public String getRolePrefix() {
        return rolePrefix;
    }

    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    public boolean isRoleToUppercase() {
        return roleToUppercase;
    }

    public void setRoleToUppercase(boolean roleToUppercase) {
        this.roleToUppercase = roleToUppercase;
    }

    public List<String> getRoleClaims() {
        return roleClaims;
    }

    @Deprecated
    public void setRoleAttributes(List<String> roleClaims) {
        this.roleClaims = roleClaims;
    }

    public void setRoleClaims(List<String> roleClaims) {
        this.roleClaims = roleClaims;
    }

    public List<String> getPermissionClaims() {
        return permissionClaims;
    }

    public void setPermissionAttibutes(List<String> permissionClaims) {
        this.permissionClaims = permissionClaims;
    }

    @Deprecated
    public void setPermissionClaims(List<String> permissionClaims) {
        this.permissionClaims = permissionClaims;
    }

    public String getUserIdClaim() {
        return userIdClaim;
    }

    public void setUserIdClaim(String userIdClaim) {
        this.userIdClaim = userIdClaim;
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

    public Set<String> getAcceptedAudiences() {
        return acceptedAudiences;
    }

    public void setAcceptedAudiences(Set<String> acceptedAudiences) {
        this.acceptedAudiences = acceptedAudiences;
    }

    public List<String> getProhibitedClaims() {
        return prohibitedClaims;
    }

    public void setProhibitedClaims(List<String> prohibitedClaims) {
        this.prohibitedClaims = prohibitedClaims;
    }
}
