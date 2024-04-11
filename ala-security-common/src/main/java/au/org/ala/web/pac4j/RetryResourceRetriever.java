package au.org.ala.web.pac4j;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import io.github.resilience4j.retry.Retry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;

/**
 * Wraps a resource retriever with retry logic in case, eg, the OIDC .well-known end point is not available.
 */
public class RetryResourceRetriever implements ResourceRetriever {

    private static final Logger log = LoggerFactory.getLogger(RetryResourceRetriever.class);

    private final ResourceRetriever other;
    private final Retry retry;

    public RetryResourceRetriever(ResourceRetriever other, Retry retry) {
        this.other = other;
        this.retry = retry;

        this.retry.getEventPublisher().onRetry( it -> {
            String message = it.getLastThrowable() == null ? "" : it.getLastThrowable().getMessage();

            log.debug("Retrying resource #{}, last error: {}", it.getNumberOfRetryAttempts(), message);
        } );
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        try {
            return Retry.decorateCheckedFunction(retry, other::retrieveResource).apply(url);
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            if (t instanceof RuntimeException) throw (RuntimeException) t;
            else if (t instanceof Error) throw (Error) t;
            else throw new RuntimeException("Unexpected exception", t);
        }
    }

}
