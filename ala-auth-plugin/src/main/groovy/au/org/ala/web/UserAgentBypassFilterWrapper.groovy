package au.org.ala.web

import groovy.json.JsonSlurper

import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern

class UserAgentBypassFilterWrapper implements Filter {

    Filter delegate

    Set<String> bypassUserAgents = ConcurrentHashMap.newKeySet()
    Set<String> acceptUserAgents = ConcurrentHashMap.newKeySet()
    List<Pattern> crawlerPatterns

    UserAgentBypassFilterWrapper(Filter delegate) {
        this.delegate = delegate
        List crawlerUserAgents = new JsonSlurper().parse(this.class.classLoader.getResource('crawler-user-agents.json'));
        crawlerPatterns = crawlerUserAgents*.pattern.collect { Pattern.compile(it) }
    }

    @Override
    void init(FilterConfig filterConfig) throws ServletException {
        delegate.init(filterConfig)
    }

    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (request instanceof HttpServletRequest) {
            def userAgent = request.getHeader('User-Agent')
            if (acceptUserAgents.contains(userAgent)) {
                this.delegate.doFilter(request, response, chain)
            } else if (bypassUserAgents.contains(userAgent)) {
                chain.doFilter(request, response)
            } else if (crawlerPatterns.any { it.matcher(userAgent).matches() }) {
                bypassUserAgents.add(userAgent)
                chain.doFilter(request, response)
            } else {
                acceptUserAgents.add(userAgent)
                this.delegate.doFilter(request, response, chain)
            }
        } else {
            this.delegate.doFilter(request, response, chain)
        }
    }

    @Override
    void destroy() {

    }
}
