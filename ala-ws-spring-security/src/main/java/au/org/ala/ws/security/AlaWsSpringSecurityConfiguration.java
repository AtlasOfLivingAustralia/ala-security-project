package au.org.ala.ws.security;

import au.org.ala.ws.security.client.AlaAuthClient;
import org.pac4j.core.config.Config;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class AlaWsSpringSecurityConfiguration {

    @Bean
    AlaWebServiceAuthFilter alaWebServiceAuthFilter(Config config, AlaAuthClient alaAuthClient) {
        return new AlaWebServiceAuthFilter(config, alaAuthClient);
    }

}
