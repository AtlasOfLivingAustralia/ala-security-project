package au.org.ala.web

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.FilterConfig
import jakarta.servlet.ServletException
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest

class UserAgentBypassFilterWrapper implements Filter {

    Filter delegate
    UserAgentFilterService userAgentFilterService

    UserAgentBypassFilterWrapper(Filter delegate, UserAgentFilterService userAgentFilterService) {
        this.delegate = delegate
        this.userAgentFilterService = userAgentFilterService
    }

    @Override
    void init(FilterConfig filterConfig) throws ServletException {
        delegate.init(filterConfig)
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {
            def userAgent = request.getHeader('User-Agent')
            def accepted = this.userAgentFilterService.isFiltered(userAgent)
            if (accepted) {
                chain.doFilter(request, response)
            } else {
                this.delegate.doFilter(request, response, chain)
            }
        } else {
            this.delegate.doFilter(request, response, chain)
        }
    }

    @Override
    void destroy() {

    }

    @Override
    String toString() {
        return "UserAgentFilterWrapper(delegate = " + delegate.toString() + ")"
    }
}
