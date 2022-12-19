package au.org.ala.ws.security;

import au.org.ala.userdetails.UserDetailsClient;
import com.google.common.collect.Lists;
import com.squareup.moshi.Moshi;
import com.squareup.moshi.adapters.Rfc3339DateJsonAdapter;
import okhttp3.Call;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import retrofit2.Retrofit;
import retrofit2.converter.moshi.MoshiConverterFactory;

import java.util.Date;
import java.util.List;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

/**
 * // TODO a lot of this is common with the ala-auth plugin,
 * so it might need to be separated into it's own library
 */
@Configuration
@EnableConfigurationProperties({ApiKeyProperties.class, UserDetailsProperties.class})
public class AlaWsSecurityRetrofitConfiguration {

    @Autowired
    private ApiKeyProperties apiKeyProperties;
    @Autowired
    private UserDetailsProperties userDetailsProperties;

    @Value("${info.app.name:Unknown-App}")
    String name;

    @Value("${info.app.version:1}")
    String version;

    @Bean("userAgentInterceptor")
    @ConditionalOnMissingBean(name = "userAgentInterceptor")
    Interceptor userAgentInterceptor() {
        String userAgent = name + "/" + version;
        return chain -> chain.proceed(
                chain.request().newBuilder()
                        .header("User-Agent", userAgent)
                        .build()
        );
    }

    /**
     * To use this with a client credentials token, you must provide a jwtInterceptor.
     * The ALA Auth and WS plugins will provide one by default but non Grails apps
     * will need to provide their own
     * @param jwtInterceptor The okhttp interceptor that inserts a bearer token onto the request
     * @param userAgentInterceptor okhttp interceptor that puts the UserAgent on the request
     * @return All interceptors for the userdetails ws client
     */
    @Bean
    @ConditionalOnMissingBean(name = "userDetailsInterceptors")
    List<Interceptor> userDetailsInterceptors(
            @Autowired(required = false) @Qualifier("jwtInterceptor") Interceptor jwtInterceptor,
            @Qualifier("userAgentInterceptor") Interceptor userAgentInterceptor) {
        var result= Lists.newArrayList(userAgentInterceptor);
        if (jwtInterceptor != null) {
            result.add(jwtInterceptor);
        }
        return result;
    }

    @ConditionalOnMissingBean(name = "userDetailsHttpClient")
    @Bean(name = {"defaultUserDetailsHttpClient", "userDetailsHttpClient"})
    OkHttpClient userDetailsHttpClient(@Qualifier("userDetailsInterceptors") List<Interceptor> userDetailsInterceptors) {
        var builder = new OkHttpClient.Builder()
                .readTimeout(userDetailsProperties.getReadTimeout(), MILLISECONDS);
        for (var interceptor : userDetailsInterceptors) {
            builder.addInterceptor(interceptor);
        }
        return builder.build();
    }

    @ConditionalOnMissingBean(name = "apikeyHttpClient")
    @Bean(name = {"defaultApikeyHttpClient", "apikeyHttpClient"})
    OkHttpClient apikeyHttpClient(@Qualifier("userAgentInterceptor") Interceptor userAgentInterceptor) {
        return new OkHttpClient.Builder()
                .readTimeout(userDetailsProperties.getReadTimeout(), MILLISECONDS)
                .addInterceptor(userAgentInterceptor)
                .build();
    }


    @ConditionalOnMissingBean(name = "userDetailsMoshi")
    @Bean(name = { "defaultUserDetailsMoshi", "userDetailsMoshi" })
    Moshi userDetailsMoshi() {
        return new Moshi.Builder()
                .add(Date.class, new Rfc3339DateJsonAdapter().nullSafe())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public UserDetailsClient userDetailsClient(
            @Qualifier("userDetailsHttpClient") OkHttpClient userDetailsHttpClient,
            @Qualifier("userDetailsMoshi") Moshi userDetailsMoshi) {
        return new UserDetailsClient.Builder((Call.Factory) userDetailsHttpClient, userDetailsProperties.getUrl())
                .moshi(userDetailsMoshi)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public ApiKeyClient apiKeyClient(
            @Qualifier("apikeyHttpClient") OkHttpClient apikeyHttpClient,
            @Qualifier("userDetailsMoshi") Moshi userDetailsMoshi) {
        return new Retrofit.Builder()
                .baseUrl(apiKeyProperties.getAuth().getServiceUrl())
                .addConverterFactory(MoshiConverterFactory.create(userDetailsMoshi))
                .client(apikeyHttpClient)
                .build()
                .create(ApiKeyClient.class);
    }

}
