package au.org.ala.security.common;

import au.org.ala.web.OidcClientProperties;
import au.org.ala.web.pac4j.CachingResourceRetriever;
import au.org.ala.web.pac4j.RetryResourceRetriever;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import io.github.resilience4j.core.IntervalFunction;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

@Configuration
@EnableConfigurationProperties(OidcClientProperties.class)
public class AlaSecurityCommonConfiguration {

    @Value("${info.app.name:Unknown-App}")
    String name;

    @Value("${info.app.version:1}")
    String version;

    @Autowired
    OidcClientProperties oidcClientProperties;

    @ConditionalOnExpression("'${security.oidc.enabled}' or '${security.jwt.enabled}'")
//    @ConditionalOnProperty(prefix = "security.oidc", name="enabled")
//    @ConditionalOnProperty({"security.oidc.enabled", "security.jwt.enabled"})
    @Bean
    public Retry oidcRetry() {

        // The retry on exception is fragile but the Resource Retriever only throws generic IOExceptions and
        // doesn't provide any structured error info to give us a way to filter only on HTTP 5xxs
        RetryConfig config = RetryConfig.custom()
                .maxAttempts(oidcClientProperties.getMaximumRetries())
                .intervalFunction(IntervalFunction.ofExponentialRandomBackoff(oidcClientProperties.getInitialRetryInterval(), 1.5d, oidcClientProperties.getMaximumRetryInterval()))
                .retryOnException(it -> it instanceof IOException && it.getMessage().startsWith("HTTP 5") ) // ResourceRetriever on detecting a 5xx response
                .retryOnException(it -> it instanceof IOException && it.getMessage().startsWith("Server returned HTTP response code: 5") ) // JDK HTTP client on attempting to get the input stream of an error response
            .build();

        return Retry.of("oidc", config);
    }

    @ConditionalOnExpression("'${security.oidc.enabled}' or '${security.jwt.enabled}'")
//    @ConditionalOnProperty({"security.oidc.enabled", "security.jwt.enabled"})
//    @ConditionalOnProperty(prefix = "security.oidc", name="enabled")
//    @ConditionalOnMissingBean
    @Bean
    public ResourceRetriever oidcResourceRetriever(@Qualifier("oidcRetry") Retry oidcRetry) {
        DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(oidcClientProperties.getConnectTimeout(), oidcClientProperties.getReadTimeout());
        String userAgent = name + "/" + version;
        resourceRetriever.setHeaders(Map.of(HttpHeaders.USER_AGENT, List.of(userAgent)));

        RetryResourceRetriever retryRetriever = new RetryResourceRetriever(resourceRetriever, oidcRetry);

        if (oidcClientProperties.isCacheLastDiscoveryDocument()) {
            return new CachingResourceRetriever(
                    retryRetriever,
                    Paths.get(oidcClientProperties.getDiscoveryDocumentCache()),
                    ( (url) -> oidcClientProperties.getDiscoveryUri().equals(url.toString()) )
            );
        } else {
            return retryRetriever;
        }
    }

}
