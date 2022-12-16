package au.org.ala.ws.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(value = "userdetails")
public class UserDetailsProperties {

    private String url = "https://auth.ala.org.au/userdetails/";

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
