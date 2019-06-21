package au.org.ala.web

import com.github.benmanes.caffeine.cache.CacheLoader
import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import groovy.transform.CompileStatic

import java.util.regex.Pattern

@CompileStatic
class UserAgentFilterService {

    LoadingCache<String,Boolean> cache
    List<Pattern> crawlerPatterns

    UserAgentFilterService(String cacheConfig, List<Pattern> crawlerPatterns) {
        if (!cacheConfig) cacheConfig = 'maximumSize=1000'
        this.crawlerPatterns = crawlerPatterns
        this.cache = Caffeine.from(cacheConfig).build(this.&isFilteredInternal as CacheLoader<String,Boolean>)
    }

    boolean isFiltered(String userAgent) {
        cache.get(userAgent)
    }

    Boolean isFilteredInternal(String userAgent) {
        return crawlerPatterns.any { it.matcher(userAgent).matches() }
    }

}
