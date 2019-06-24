package au.org.ala.web

import groovy.transform.CompileStatic

import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest

/**
 * Java Servlet Filter wrapper that will only execute a filter if a cookie is present
 */
@CompileStatic
class CookieFilterWrapper implements Filter {

    private final Filter filter
    private final String cookieName

    CookieFilterWrapper(Filter filter, String cookieName) {
        this.filter = filter
        this.cookieName = cookieName
    }

    @Override
    void init(FilterConfig filterConfig) throws ServletException {
        this.filter.init(filterConfig)
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            if (request.cookies.any { Cookie cookie -> cookie.name == this.cookieName && cookie.value }) {
                filter.doFilter(request, response, chain)
            } else {
                chain.doFilter(request, response)
            }
        } else {
            chain.doFilter(request, response)
        }
    }

    @Override
    void destroy() {
        this.filter.destroy()
    }

    @Override
    String toString() {
        return "CookieFilterWrapper(cookieName = " + cookieName + " delegate = " + filter.toString() + ")"
    }
}
