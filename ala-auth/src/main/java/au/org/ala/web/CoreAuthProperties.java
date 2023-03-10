package au.org.ala.web;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(value = "security.core")
public class CoreAuthProperties {
    private String authCookieName;
    private String roleAttribute;
    private List<String> permissionAttributes = new ArrayList<>();

    private List<String> uriFilterPattern = new ArrayList<>();
    private List<String> optionalFilterPattern = new ArrayList<>();
    private List<String> uriExclusionFilterPattern = new ArrayList<>();
    private String defaultLogoutRedirectUri = "/";
    private String logoutUrlPattern = null; // Pac4j will default to the default value if this is null
    private boolean centralLogout = true;
    private boolean destroySession = true;
    private boolean localLogout = true;

    public List<String> getUriFilterPattern() {
        return uriFilterPattern;
    }

    public void setUriFilterPattern(List<String> uriFilterPattern) {
        this.uriFilterPattern = uriFilterPattern;
    }

    public List<String> getOptionalFilterPattern() {
        return optionalFilterPattern;
    }

    public void setOptionalFilterPattern(List<String> optionalFilterPattern) {
        this.optionalFilterPattern = optionalFilterPattern;
    }

    public String getAuthCookieName() {
        return authCookieName;
    }

    public void setAuthCookieName(String authCookieName) {
        this.authCookieName = authCookieName;
    }

    public List<String> getUriExclusionFilterPattern() {
        return uriExclusionFilterPattern;
    }

    public void setUriExclusionFilterPattern(List<String> uriExclusionFilterPattern) {
        this.uriExclusionFilterPattern = uriExclusionFilterPattern;
    }

    public String getRoleAttribute() {
        return roleAttribute;
    }

    public void setRoleAttribute(String roleAttribute) {
        this.roleAttribute = roleAttribute;
    }

    public List<String> getPermissionAttributes() {
        return permissionAttributes;
    }

    public void setPermissionAttributes(List<String> permissionAttributes) {
        this.permissionAttributes = permissionAttributes;
    }

    public String getDefaultLogoutRedirectUri() {
        return defaultLogoutRedirectUri;
    }

    public void setDefaultLogoutRedirectUri(String defaultLogoutRedirectUri) {
        this.defaultLogoutRedirectUri = defaultLogoutRedirectUri;
    }

    public boolean isCentralLogout() {
        return centralLogout;
    }

    public void setCentralLogout(boolean centralLogout) {
        this.centralLogout = centralLogout;
    }

    public boolean isDestroySession() {
        return destroySession;
    }

    public void setDestroySession(boolean destroySession) {
        this.destroySession = destroySession;
    }

    public boolean isLocalLogout() {
        return localLogout;
    }

    public void setLocalLogout(boolean localLogout) {
        this.localLogout = localLogout;
    }

    public String getLogoutUrlPattern() {
        return logoutUrlPattern;
    }

    public void setLogoutUrlPattern(String logoutUrlPattern) {
        this.logoutUrlPattern = logoutUrlPattern;
    }
}
