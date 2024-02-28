package au.org.ala.web.pac4j

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.util.Resource
import com.nimbusds.jose.util.ResourceRetriever
import groovy.util.logging.Slf4j

import java.nio.file.Path
import java.util.function.Function


@Slf4j
class CachingResourceRetriever implements ResourceRetriever {

    private final ResourceRetriever other
    private final Path cachePath

    private final ObjectMapper objectMapper = new ObjectMapper()
    private final Function<URL, Boolean> filterFunction

    CachingResourceRetriever(ResourceRetriever other, Path cachePath, Function<URL, Boolean> filterFunction) {

        this.filterFunction = filterFunction
        this.cachePath = cachePath
        this.other = other
    }

    @Override
    Resource retrieveResource(URL url) throws IOException {
        Resource resource
        boolean cacheResource = false
        try {
            resource = other.retrieveResource(url)
            cacheResource = filterFunction(url)
        } catch (Exception e) {
            log.error("Couldn't load resource from $url, attempting to load cached version")
            resource = loadResource()
            if (!resource) {
                log.error("Couldn't load cached resource for $url, rethrowing exception...")
                throw e
            }
        }

        if (cacheResource) {
            saveResource(resource)
        }

        return resource
    }

    private void saveResource(Resource resource) {
        def file = cachePath.toFile()
        if (file.canWrite()) {
            try {
                objectMapper.writeValue(file, resource)
            } catch (Exception e) {
                log.debug("Couldn't save cache file $file", e)
            }
        } else {
            log.warn("Can't write to $file")
        }
    }

    private Resource loadResource() {
        def file = cachePath.toFile()
        if (file.exists() && file.canRead()) {
            try {
                return objectMapper.readValue(file, Resource)
            } catch (Exception e) {
                log.debug("Couldn't read resource cache file $file", e)
                return null
            }
        } else {
            log.warn("Couldn't read from $file")
            return null
        }
    }
}
