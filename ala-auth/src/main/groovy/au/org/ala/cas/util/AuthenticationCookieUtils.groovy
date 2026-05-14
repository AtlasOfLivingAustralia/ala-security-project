package au.org.ala.cas.util

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest

/**
 * Minimal compatibility utility retained for legacy callers.
 */
class AuthenticationCookieUtils {

    static final String ALA_AUTH_COOKIE = System.getProperty('ala.auth.cookie.name', 'ALA-Auth')

    static boolean cookieExists(HttpServletRequest request, String cookieName = ALA_AUTH_COOKIE) {
        if (!request?.cookies || !cookieName) {
            return false
        }
        return request.cookies.any { Cookie c -> c?.name == cookieName }
    }
}

