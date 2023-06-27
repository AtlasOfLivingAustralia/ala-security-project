package au.org.ala.ws.config


import au.org.ala.ws.tokens.TokenService
import org.pac4j.core.config.Config
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration

import javax.annotation.PostConstruct

@Configuration class AlaWsPluginTokenServiceConfig {

    @Autowired
    TokenService tokenService
    @Autowired
    Config config

    /**
     * Injecting the PAC4j Config into the TokenService can cause a circular dependency.
     * Since the Config isn't used in the construction of the TokenService, we inject
     * it after construction instead.
     */
    @PostConstruct
    void setConfigOnTokenService() {
        tokenService.setConfig(config)
    }

}
