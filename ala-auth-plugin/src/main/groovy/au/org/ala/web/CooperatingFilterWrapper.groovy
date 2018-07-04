package au.org.ala.web

import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

class CooperatingFilterWrapper implements Filter {

    private final Filter delegate
    private final String key

    CooperatingFilterWrapper(Filter delegate, String key) {
        this.key = key
        this.delegate = delegate
    }

    @Override
    void init(FilterConfig filterConfig) throws ServletException {
        delegate.init(filterConfig)
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request.getAttribute(key)) {
            chain.doFilter(request, response)
        } else {
            request.setAttribute(key, Boolean.TRUE)
            delegate.doFilter(request, response, chain)
            request.removeAttribute(key)
        }
    }

    @Override
    void destroy() {

    }
}
