package au.org.ala.web.config;

import au.org.ala.web.SpringSessionLogoutHandler
import org.pac4j.core.logout.handler.LogoutHandler
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.session.SessionAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.session.FindByIndexNameSessionRepository
import org.springframework.session.Session

@Configuration
@ConditionalOnClass(FindByIndexNameSessionRepository.class)
@ConditionalOnProperty(prefix = 'spring.session', name = 'enabled', havingValue = "true")
@AutoConfigureAfter(SessionAutoConfiguration.class)
class SpringSessionPluginConfig {
    @Bean
    @ConditionalOnBean(FindByIndexNameSessionRepository.class)
    <S extends Session> LogoutHandler oidcLogoutHandler(FindByIndexNameSessionRepository<S> repository) {
        new SpringSessionLogoutHandler(repository)
    }
}
