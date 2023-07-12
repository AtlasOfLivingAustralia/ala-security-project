package au.org.ala.web;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * When OIDC is enabled this can be enabled to set an ALA CAS backwards compatible cookie that hints to
 * apps that share the same domain name that a user is probably logged in to the OIDC RP.
 */
@ConfigurationProperties(value = "security.cookie")
public class AuthCookieProperties {
    /** Whether to enable adding a cookie after the login completes */
    private boolean enabled = false;

    /** The domain to add the cookie to, by default is ALA top level */
    private String domain = ".ala.org.au";
    /** The path the auth cookie should be applied to, defaults to '/' */
    private String path = "/";
    /** Whether the cookie should be http only, false by default */
    private boolean httpOnly = false;
    /** Whether the cookie should be secure, false by default */
    private boolean secure = true;
    private String securityPolicy;
    private String comment;

    private Integer maxAge = -1;

    private boolean quoteValue = true;
    private boolean encodeValue = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }

    public void setHttpOnly(boolean httpOnly) {
        this.httpOnly = httpOnly;
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    public String getSecurityPolicy() {
        return securityPolicy;
    }

    public void setSecurityPolicy(String securityPolicy) {
        this.securityPolicy = securityPolicy;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public Integer getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(Integer maxAge) {
        this.maxAge = maxAge;
    }

    public boolean isQuoteValue() {
        return quoteValue;
    }

    public void setQuoteValue(boolean quoteValue) {
        this.quoteValue = quoteValue;
    }

    public boolean isEncodeValue() {
        return encodeValue;
    }

    public void setEncodeValue(boolean encodeValue) {
        this.encodeValue = encodeValue;
    }
}
