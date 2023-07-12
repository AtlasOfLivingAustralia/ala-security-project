package au.org.ala.pac4j.core

import org.pac4j.jee.context.JEEContextFactory
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import spock.lang.Specification

import javax.servlet.http.Cookie

class CookieGeneratorSpec extends Specification {

    def "test addCookie"() {
        setup:
        def cg = new CookieGenerator(true, 'name', 'ala.example', '/', false, true, -1, 'lax', 'comment', true, false)
        def request = new MockHttpServletRequest('GET', '/')
        def response = new MockHttpServletResponse()
        def ctx = JEEContextFactory.INSTANCE.newContext(request, response)

        when:
        cg.addCookie(ctx, 'test')
        def cookie = response.getCookie('name')

        then:
        cookie != null
        cookie.domain == 'ala.example'
        cookie.path == '/'
        cookie.value == '"test"'
        !cookie.httpOnly
        cookie.secure
        cookie.maxAge == -1
        // Ignored - pac4j doesn't add the comment to the cookie header it creates.
//        cookie.comment == 'comment'
    }

    def "test removeCookie"() {
        setup:
        def cg = new CookieGenerator(true, 'name', 'ala.example', '/', false, true, -1, 'lax', 'comment', true, false)
        def request = new MockHttpServletRequest('GET', '/')
        request.cookies = new Cookie('name', '"test"').tap { it.maxAge = -1; it.path = '/'; it.domain = 'ala.example' }
        def response = new MockHttpServletResponse()
        def ctx = JEEContextFactory.INSTANCE.newContext(request, response)

        when:
        cg.removeCookie(ctx)
        def cookie = response.getCookie('name')

        then:
        cookie != null
        cookie.domain == 'ala.example'
        cookie.path == '/'
        cookie.value == ''
        !cookie.httpOnly
        cookie.secure
        cookie.maxAge == 0
    }

}
