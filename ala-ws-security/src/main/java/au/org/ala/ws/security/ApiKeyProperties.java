package au.org.ala.ws.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(value = "security.apikey")
public class ApiKeyProperties {

    private boolean enabled = true;

    private HeaderProperties header = new HeaderProperties();

    private WebServiceProperties auth = new WebServiceProperties();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public HeaderProperties getHeader() {
        return header;
    }

    public void setHeader(HeaderProperties header) {
        this.header = header;
    }

    public WebServiceProperties getAuth() {
        return auth;
    }

    public void setAuth(WebServiceProperties auth) {
        this.auth = auth;
    }

    public class HeaderProperties {

        private String override = "apiKey";

        private List<String> alternatives = List.of();

        public String getOverride() {
            return override;
        }

        public void setOverride(String override) {
            this.override = override;
        }

        public List<String> getAlternatives() {
            return alternatives;
        }

        public void setAlternatives(List<String> alternatives) {
            this.alternatives = alternatives;
        }
    }

    public class WebServiceProperties {

        private String serviceUrl;

        public String getServiceUrl() {
            return serviceUrl;
        }

        public void setServiceUrl(String serviceUrl) {
            this.serviceUrl = serviceUrl;
        }
    }
}
