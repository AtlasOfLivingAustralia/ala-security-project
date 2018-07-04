package au.org.ala.web;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(value = "security.cas")
public class CasClientProperties {

    public String appServerName;
    public String service;
    public String casServerName;
    public String casServerUrlPrefix;
    public String loginUrl;
    public String logoutUrl;
    public boolean enabled = true;
    public boolean gateway;
    public boolean renew;
    public List<String> uriFilterPattern = new ArrayList<>();
    public List<String> uriExclusionFilterPattern = new ArrayList<>();
    public List<String> authenticateOnlyIfLoggedInPattern = new ArrayList<>();
    public List<String> authenticateOnlyIfLoggedInFilterPattern = new ArrayList<>();
    public String gatewayStorageClass;
    public String roleAttribute = "role";
    public boolean ignoreCase = true;
    public boolean encodeServiceUrl = true;
    public String contextPath = null;

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

}
