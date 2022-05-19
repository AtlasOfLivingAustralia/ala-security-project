package au.org.ala.web;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(value = "security.cas")
public class CasClientProperties {

    private String appServerName;
    private String service;
    private String casServerName;
    private String casServerUrlPrefix;
    private String loginUrl;
    private String logoutUrl;
    private boolean enabled = true;
    private boolean gateway = false;
    private boolean renew = false;
    private List<String> uriFilterPattern = new ArrayList<>();
    private List<String> uriExclusionFilterPattern = new ArrayList<>();
    private List<String> authenticateOnlyIfLoggedInPattern = new ArrayList<>();
    private List<String> authenticateOnlyIfLoggedInFilterPattern = new ArrayList<>();
    private List<String> authenticateOnlyIfCookieFilterPattern = new ArrayList<>();
    private List<String> gatewayIfCookieFilterPattern = new ArrayList<>();
    private List<String> gatewayFilterPattern = new ArrayList<>();
    private String gatewayStorageClass;
    private String roleAttribute = "role";
    private boolean ignoreCase = true;
    private boolean encodeServiceUrl = true;
    private boolean bypass = false;
    private String contextPath = null;
    @Deprecated
    private String authCookieName = "ALA-Auth";

    public String getAppServerName() {
        return appServerName;
    }

    public void setAppServerName(String appServerName) {
        this.appServerName = appServerName;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getCasServerName() {
        return casServerName;
    }

    public void setCasServerName(String casServerName) {
        this.casServerName = casServerName;
    }

    public String getCasServerUrlPrefix() {
        return casServerUrlPrefix;
    }

    public void setCasServerUrlPrefix(String casServerUrlPrefix) {
        this.casServerUrlPrefix = casServerUrlPrefix;
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isGateway() {
        return gateway;
    }

    public void setGateway(boolean gateway) {
        this.gateway = gateway;
    }

    public boolean isRenew() {
        return renew;
    }

    public void setRenew(boolean renew) {
        this.renew = renew;
    }

    public List<String> getUriFilterPattern() {
        return uriFilterPattern;
    }

    public void setUriFilterPattern(List<String> uriFilterPattern) {
        this.uriFilterPattern = uriFilterPattern;
    }

    public List<String> getUriExclusionFilterPattern() {
        return uriExclusionFilterPattern;
    }

    public void setUriExclusionFilterPattern(List<String> uriExclusionFilterPattern) {
        this.uriExclusionFilterPattern = uriExclusionFilterPattern;
    }

    public List<String> getAuthenticateOnlyIfLoggedInPattern() {
        return authenticateOnlyIfLoggedInPattern;
    }

    public void setAuthenticateOnlyIfLoggedInPattern(List<String> authenticateOnlyIfLoggedInPattern) {
        this.authenticateOnlyIfLoggedInPattern = authenticateOnlyIfLoggedInPattern;
    }

    public List<String> getAuthenticateOnlyIfLoggedInFilterPattern() {
        return authenticateOnlyIfLoggedInFilterPattern;
    }

    public void setAuthenticateOnlyIfLoggedInFilterPattern(List<String> authenticateOnlyIfLoggedInFilterPattern) {
        this.authenticateOnlyIfLoggedInFilterPattern = authenticateOnlyIfLoggedInFilterPattern;
    }

    public String getGatewayStorageClass() {
        return gatewayStorageClass;
    }

    public void setGatewayStorageClass(String gatewayStorageClass) {
        this.gatewayStorageClass = gatewayStorageClass;
    }

    public String getRoleAttribute() {
        return roleAttribute;
    }

    public void setRoleAttribute(String roleAttribute) {
        this.roleAttribute = roleAttribute;
    }

    public boolean isIgnoreCase() {
        return ignoreCase;
    }

    public void setIgnoreCase(boolean ignoreCase) {
        this.ignoreCase = ignoreCase;
    }

    public boolean isEncodeServiceUrl() {
        return encodeServiceUrl;
    }

    public void setEncodeServiceUrl(boolean encodeServiceUrl) {
        this.encodeServiceUrl = encodeServiceUrl;
    }

    public String getContextPath() {
        return contextPath;
    }

    public void setContextPath(String contextPath) {
        this.contextPath = contextPath;
    }

    public List<String> getAuthenticateOnlyIfCookieFilterPattern() {
        return authenticateOnlyIfCookieFilterPattern;
    }

    public void setAuthenticateOnlyIfCookieFilterPattern(List<String> authenticateOnlyIfCookieFilterPattern) {
        this.authenticateOnlyIfCookieFilterPattern = authenticateOnlyIfCookieFilterPattern;
    }

    public List<String> getGatewayIfCookieFilterPattern() {
        return gatewayIfCookieFilterPattern;
    }

    public void setGatewayIfCookieFilterPattern(List<String> gatewayIfCookieFilterPattern) {
        this.gatewayIfCookieFilterPattern = gatewayIfCookieFilterPattern;
    }

    public String getAuthCookieName() {
        return authCookieName;
    }

    public void setAuthCookieName(String authCookieName) {
        this.authCookieName = authCookieName;
    }

    public List<String> getGatewayFilterPattern() {
        return gatewayFilterPattern;
    }

    public void setGatewayFilterPattern(List<String> gatewayFilterPattern) {
        this.gatewayFilterPattern = gatewayFilterPattern;
    }

    public boolean isBypass() {
        return bypass;
    }

    public void setBypass(boolean bypass) {
        this.bypass = bypass;
    }
}
