package au.org.ala.web.config

import au.org.ala.web.mongo.Pac4jJdkMongoSessionConverter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfigureAfter
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.session.SessionProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.session.data.mongo.AbstractMongoSessionConverter
import org.springframework.session.data.mongo.JacksonMongoSessionConverter
import org.springframework.session.data.mongo.JdkMongoSessionConverter
import org.springframework.session.data.mongo.MongoSession

@Configuration
@ConditionalOnClass(MongoSession)
@ConditionalOnProperty(prefix = 'spring.session', name = 'store-type', havingValue = "mongodb")
@AutoConfigureAfter(SpringSessionPluginConfig.class)
@EnableConfigurationProperties(SessionProperties)
class MongoSpringSessionPluginConfig {

    @Autowired
    SessionProperties sessionProperties

    @Bean
    @ConditionalOnMissingBean([
            AbstractMongoSessionConverter,
            JdkMongoSessionConverter,
            JacksonMongoSessionConverter
    ])
    JdkMongoSessionConverter sessionConverter() {
        new Pac4jJdkMongoSessionConverter(sessionProperties.getTimeout())
    }
}
