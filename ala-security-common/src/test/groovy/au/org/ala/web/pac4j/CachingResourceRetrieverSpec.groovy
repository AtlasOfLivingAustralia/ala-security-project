package au.org.ala.web.pac4j

import com.nimbusds.jose.util.Resource
import com.nimbusds.jose.util.ResourceRetriever
import spock.lang.Specification

class CachingResourceRetrieverSpec extends Specification {

    def 'test cached retrieve resource'() {
        setup:
        def tempPath = File.createTempFile('caching-resource-retriever-spec', '.json')
        def rr = Mock(ResourceRetriever)
        def crr = new CachingResourceRetriever(rr, tempPath.toPath(), { true })

        def url = new URL('https://example.org')

        when:
        def r1 = crr.retrieveResource(url)
        def r2 = crr.retrieveResource(url)

        then:
        2 * rr.retrieveResource(url) >> new Resource('{"foo": "bar"}', 'application/json') >> { throw new IOException("HTTP 500") }
        tempPath.text == '{"content":"{\\"foo\\": \\"bar\\"}","contentType":"application/json"}'

        r1.content == r2.content
        r1.contentType == r2.contentType

        cleanup:
        tempPath.delete()
    }
}
