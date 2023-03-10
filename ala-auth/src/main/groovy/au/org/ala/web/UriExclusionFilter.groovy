package au.org.ala.web

import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest

/**
 * Simple filter wrapper that skips the filter if the request URI starts with the given path.
 * The intended use of this is to prevent filters being applied to Spring Boot actuator endpoints.
 *
 * The path comparision is simply: "does the request URI minus the context path start with a given path?"
 */
class UriExclusionFilter implements Filter {

    private Filter delegate
    private String path

    UriExclusionFilter(Filter delegate, String path) {
        this.delegate = delegate
        this.path = path
    }

    @Override
    void init(FilterConfig filterConfig) throws ServletException {
        delegate.init(filterConfig)
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            final httpRequest = (HttpServletRequest) request
            final ctx = httpRequest.contextPath
            def uri = httpRequest.requestURI
            if (uri.startsWith(ctx)) uri = uri.substring(ctx.length())

            if (uri.startsWith(path)) {
                chain.doFilter(request, response)
            } else {
                delegate.doFilter(request, response, chain)
            }
        } else {
            chain.doFilter(request, response)
        }
    }

    @Override
    void destroy() {
        delegate.destroy()
    }
}
