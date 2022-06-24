package au.org.ala.web.config;

import au.org.ala.web.SpringSessionLogoutHandler
import org.pac4j.core.logout.handler.LogoutHandler
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.session.FindByIndexNameSessionRepository
import org.springframework.session.Session

@Configuration
@ConditionalOnClass(name = 'org.springframework.session.SessionRepository')
@ConditionalOnProperty(prefix = 'spring.session', name = 'enabled')
class SpringSessionPluginConfig {
    @Bean
    <S extends Session> LogoutHandler oidcLogoutHandler(FindByIndexNameSessionRepository<S> repository) {
        new SpringSessionLogoutHandler(repository)
    }
}
