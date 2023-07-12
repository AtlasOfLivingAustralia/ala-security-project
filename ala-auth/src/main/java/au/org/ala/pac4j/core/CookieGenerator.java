package au.org.ala.pac4j.core;

import org.pac4j.core.context.Cookie;
import org.pac4j.core.context.WebContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class CookieGenerator {

    private static final Logger log = LoggerFactory.getLogger(CookieGenerator.class);

    boolean enabled;
    String name;
    String domain;
    String path = "/";
    boolean httpOnly;
    boolean secure;
    int maxAge;

    String securityPolicy;
    String comment;

    boolean quoteCookieValue;// = true
    boolean encodeCookieValue;// = false

    public CookieGenerator(boolean enabled, String name, String domain, String path, boolean httpOnly, boolean secure,
                           int maxAge, String securityPolicy, String comment, boolean quoteCookieValue,
                           boolean encodeCookieValue) {
        this.enabled = enabled;
        this.name = name;
        this.domain = domain;
        this.path = path;
        this.httpOnly = httpOnly;
        this.secure = secure;
        this.maxAge = maxAge;
        this.securityPolicy = securityPolicy;
        this.comment = comment;
        this.quoteCookieValue = quoteCookieValue;
        this.encodeCookieValue = encodeCookieValue;
    }

    public void addCookie(WebContext ctx, String value) {
        if (enabled) {
            if (ctx.getRequestCookies().stream().anyMatch( it -> Objects.equals(it.getName(), this.name) && it.getMaxAge() == this.maxAge)) {
                log.debug("Not adding $name cookie because it already exists");
                return;
            }
            var cookie = createCookie(quoteValue(encodeValue(value)), maxAge);
            if (comment != null && !comment.isBlank()) {
                cookie.setComment(this.comment);
            }
            if (securityPolicy != null && !securityPolicy.isBlank()) {
                cookie.setSameSitePolicy(this.securityPolicy);
            }
            ctx.addResponseCookie(cookie);
        }
    }

    public void removeCookie(WebContext ctx) {
        if (enabled) {
            var existing = ctx.getRequestCookies().stream().anyMatch( it -> Objects.equals(it.getName(), this.name));
            if (existing) {
                ctx.addResponseCookie(createCookie("", 0));
            }
        }
    }

    private Cookie createCookie(String value, int maxAge) {
        var cookie = new Cookie(name, value);
        if (domain != null && !domain.isBlank()) {
            cookie.setDomain(domain);
        }
        cookie.setPath(path);
        cookie.setHttpOnly(this.httpOnly);
        cookie.setSecure(this.secure);
        cookie.setMaxAge(maxAge);

        return cookie;
    }

    private String quoteValue(String value) {
        if (quoteCookieValue) {
            return "\""+value+"\"";
        } else {
            return value;
        }
    }

    private String encodeValue(String value) {
        if (encodeCookieValue) {
            // TODO Custom encoder that doesn't encode valid cookie characters
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        } else {
            return value;
        }
    }
}
