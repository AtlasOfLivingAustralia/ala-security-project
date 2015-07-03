package au.org.ala.ws.security.service

import grails.converters.JSON

class ApiKeyService {
    def grailsApplication
    WebService webService

    static final int STATUS_OK = 200

    Map checkApiKey(String key) {
        Map response

        try {
            def conn = webService.get("${grailsApplication.config.security.apikey.check.serviceUrl}${key}")

            if (conn.responseCode == STATUS_OK) {
                response = JSON.parse(conn.content.text as String)
                if (!response.valid) {
                    log.info "Rejected - " + (key ? "using key ${key}" : "no key present")
                }
            } else {
                log.info "Rejected - " + (key ? "using key ${key}" : "no key present")
                response = [valid: false]
            }
        } catch (Exception e) {
            log.error "Failed to lookup key ${key}", e
            response = [valid: false]
        }

        return response
    }
}
