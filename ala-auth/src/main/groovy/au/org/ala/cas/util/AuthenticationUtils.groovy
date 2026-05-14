package au.org.ala.cas.util

import jakarta.servlet.http.HttpServletRequest

class AuthenticationUtils {
    static String getEmailAddress(HttpServletRequest request) {
        getPrincipalAttribute(request, 'email')
    }

    static String getUserId(HttpServletRequest request) {
        getPrincipalAttribute(request, 'userid') ?: getPrincipalAttribute(request, 'userId')
    }

    static String getDisplayName(HttpServletRequest request) {
        String first = getFirstName(request)
        String last = getLastName(request)
        if (first || last) {
            return [first, last].findAll { it }?.join(' ')
        }
        request?.userPrincipal?.name
    }

    static String getFirstName(HttpServletRequest request) {
        getPrincipalAttribute(request, 'firstname') ?: getPrincipalAttribute(request, 'firstName')
    }

    static String getLastName(HttpServletRequest request) {
        getPrincipalAttribute(request, 'lastname') ?: getPrincipalAttribute(request, 'lastName')
    }

    static String getPrincipalAttribute(HttpServletRequest request, String name) {
        if (!request || !name) return null
        Map attrs = resolvePrincipalAttributes(request)
        if (!attrs) return null

        def value = attrs[name]
        if (value == null) {
            def entry = attrs.find { k, v -> k?.toString()?.equalsIgnoreCase(name) }
            value = entry?.value
        }
        if (value instanceof Collection) {
            return value.find { it != null }?.toString()
        }
        value?.toString()
    }

    static boolean isUserInRole(HttpServletRequest request, String role) {
        if (!request || !role) return false
        request.isUserInRole(role) || getUserRoles(request).contains(role)
    }

    static Set<String> getUserRoles(HttpServletRequest request) {
        Map attrs = resolvePrincipalAttributes(request)
        if (!attrs) return [] as Set<String>

        def roles = attrs['roles'] ?: attrs['role'] ?: attrs['authorities']
        if (roles == null) return [] as Set<String>

        if (roles instanceof Collection) {
            return roles.findAll { it != null }.collect { it.toString() } as Set<String>
        }
        roles.toString().split(',').collect { it.trim() }.findAll { it } as Set<String>
    }

    private static Map resolvePrincipalAttributes(HttpServletRequest request) {
        def principal = request?.userPrincipal
        if (principal == null) return [:]

        def attrs = null
        try {
            attrs = principal.attributes
        } catch (MissingPropertyException ignored) {
            attrs = null
        }
        if (attrs instanceof Map) {
            return attrs as Map
        }
        [:]
    }
}

