package au.org.ala.web

import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest

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
