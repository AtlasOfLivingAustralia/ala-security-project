package au.org.ala.web.pac4j;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.util.function.Function;


public class CachingResourceRetriever implements ResourceRetriever {

    private final static Logger log = LoggerFactory.getLogger(CachingResourceRetriever.class);

    private final ResourceRetriever other;
    private final Path cachePath;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Function<URL, Boolean> filterFunction;

    public CachingResourceRetriever(ResourceRetriever other, Path cachePath, Function<URL, Boolean> filterFunction) {

        this.filterFunction = filterFunction;
        this.cachePath = cachePath;
        this.other = other;

        objectMapper.addMixIn(Resource.class, ResourceMixIn.class);
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        Resource resource;
        boolean cacheResource = false;
        try {
            resource = other.retrieveResource(url);
            cacheResource = filterFunction.apply(url);
        } catch (Exception e) {
            log.error("Couldn't load resource from {}, attempting to load cached version", url);
            resource = loadResource();
            if (resource == null) {
                log.error("Couldn't load cached resource for {}, rethrowing exception...", url);
                throw e;
            }
        }

        if (cacheResource) {
            saveResource(resource);
        }

        return resource;
    }

    private void saveResource(Resource resource) {
        File file = cachePath.toFile();
        if (file.canWrite()) {
            try {
                objectMapper.writeValue(file, resource);
            } catch (Exception e) {
                log.debug("Couldn't save cache file {}", file, e);
            }
        } else {
            log.warn("Can't write to {}", file);
        }
    }

    private Resource loadResource() {
        File file = cachePath.toFile();
        if (file.exists() && file.canRead()) {
            try {
                return objectMapper.readValue(file, Resource.class);
            } catch (Exception e) {
                log.debug("Couldn't read resource cache file {}", file, e);
                return null;
            }
        } else {
            log.warn("Couldn't read from {}", file);
            return null;
        }
    }

    static class ResourceMixIn {
        ResourceMixIn(@JsonProperty("content") String content, @JsonProperty("contentType") String contentType) { }
    }
}
