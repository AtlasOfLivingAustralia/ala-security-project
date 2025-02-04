package au.ala.org.ws.security.filter;

import au.ala.org.ws.security.RequireApiKey;
import grails.web.api.ServletAttributes;

@FunctionalInterface
public interface RequireApiKeyFilter {

    /**
     * Check if the request is allowed to proceed based on the annotation and the servlet attributes.
     *
     * @param annotation the annotation
     * @param servletAttributes This will probably be the interceptor instance
     * @return true if the request is allowed to proceed
     */
    boolean isAllowed(RequireApiKey annotation, ServletAttributes servletAttributes);

}
