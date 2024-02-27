package au.org.ala.web.pac4j

import com.nimbusds.jose.util.Resource
import com.nimbusds.jose.util.ResourceRetriever
import groovy.util.logging.Slf4j
import io.github.resilience4j.retry.Retry

/**
 * Wraps a resource retriever with retry logic in case, eg, the OIDC .well-known end point is not available.
 */
@Slf4j
class RetryResourceRetriever implements ResourceRetriever {

    private final ResourceRetriever other
    private final Retry retry

    RetryResourceRetriever(ResourceRetriever other, Retry retry) {
        this.other = other
        this.retry = retry

        this.retry.eventPublisher.onRetry { log.debug("Retrying resource #{}, last error: {}", it.numberOfRetryAttempts, it.lastThrowable.message) }
    }

    @Override
    Resource retrieveResource(URL url) throws IOException {
        return Retry.decorateCheckedFunction(retry, other::retrieveResource).apply(url)
    }
}
