package au.org.ala.web.config

import au.org.ala.userdetails.UserDetailsClient
import com.squareup.moshi.Moshi
import com.squareup.moshi.Rfc3339DateJsonAdapter
import grails.core.GrailsApplication
import groovy.transform.CompileStatic
import okhttp3.OkHttpClient
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

import static java.util.concurrent.TimeUnit.MILLISECONDS

@CompileStatic
@Configuration("alaAuthPluginConfiguration")
class AuthPluginConfig {

    @ConditionalOnMissingBean(name = "userDetailsHttpClient")
    @Bean(name = ["defaultUserDetailsHttpClient", "userDetailsHttpClient"])
    OkHttpClient userDetailsHttpClient(GrailsApplication grailsApplication) {
        Integer readTimeout = (grailsApplication.config['userDetails']['readTimeout'] ?: '60000') as Integer
        new OkHttpClient.Builder().readTimeout(readTimeout, MILLISECONDS).build()
    }

    @ConditionalOnMissingBean(name = "userDetailsMoshi")
    @Bean(name = ["defaultUserDetailsMoshi", "userDetailsMoshi"])
    Moshi userDetailsMoshi() {
        new Moshi.Builder().add(Date, new Rfc3339DateJsonAdapter()).build()
    }


    @Bean("userDetailsClient")
    UserDetailsClient userDetailsClient(@Qualifier("userDetailsHttpClient") OkHttpClient userDetailsHttpClient,
                                        @Qualifier('userDetailsMoshi') Moshi moshi,
                                        GrailsApplication grailsApplication) {
        String baseUrl = grailsApplication.config["userDetails"]["url"] ?: 'https://auth.ala.org.au/userdetails/'
        new UserDetailsClient.Builder(userDetailsHttpClient, baseUrl).moshi(moshi).build()
    }

}
