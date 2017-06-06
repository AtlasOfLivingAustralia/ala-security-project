package au.org.ala.web.filter;

import javax.servlet.*;
import java.io.IOException;
import java.util.*;

public class ParametersFilterProxy implements Filter {

    private Filter filter;

    private Map<String,String> initParameters;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Map<String, String> parameters = this.initParameters;
        if (parameters == null) {
            parameters = new HashMap<String,String>();
        }
        filter.init(new FilterConfigWrapper(filterConfig, parameters));
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        filter.doFilter(servletRequest, servletResponse, filterChain);
    }

    @Override
    public void destroy() {
        filter.destroy();
    }

    public Filter getFilter() {
        return filter;
    }

    public void setFilter(Filter filter) {
        this.filter = filter;
    }

    public Map<String, String> getInitParameters() {
        return initParameters;
    }

    public void setInitParameters(Map<String, String> initParameters) {
        this.initParameters = initParameters;
    }

    private static class FilterConfigWrapper implements FilterConfig {

        private final FilterConfig filterConfig;
        private final Map<String, String> initParameters;

        FilterConfigWrapper(FilterConfig filterConfig, Map<String, String> initParams) {
            this.filterConfig = filterConfig;
            this.initParameters = initParams;
        }

        @Override
        public String getFilterName() {
            return filterConfig.getFilterName();
        }

        @Override
        public ServletContext getServletContext() {
            return filterConfig.getServletContext();
        }

        @Override
        public String getInitParameter(String name) {
            String value = initParameters.get(name);
            if (value == null) {
                return filterConfig.getInitParameter(name);
            }
            return value;
        }

        @Override
        public Enumeration<String> getInitParameterNames() {
            HashSet<String> names = new HashSet<String>();
            names.addAll(initParameters.keySet());
            names.addAll(Collections.list(filterConfig.getInitParameterNames()));
            return Collections.enumeration(names);
        }
    }
}