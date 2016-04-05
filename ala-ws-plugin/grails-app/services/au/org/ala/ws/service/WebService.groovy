package au.org.ala.ws.service

import au.org.ala.web.AuthService
import grails.converters.JSON
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.Method
import org.apache.http.HttpEntity
import org.apache.http.HttpStatus
import org.apache.http.client.config.RequestConfig
import org.apache.http.entity.ContentType
import org.apache.http.entity.mime.MultipartEntityBuilder
import org.apache.http.entity.mime.content.ByteArrayBody
import org.apache.http.entity.mime.content.StringBody
import org.springframework.web.multipart.commons.CommonsMultipartFile
import javax.servlet.http.HttpServletResponse

import static groovyx.net.http.Method.*
import static org.codehaus.groovy.grails.web.servlet.HttpHeaders.CONNECTION
import static org.codehaus.groovy.grails.web.servlet.HttpHeaders.CONTENT_DISPOSITION
import static org.codehaus.groovy.grails.web.servlet.HttpHeaders.TRANSFER_ENCODING

class WebService {
    static final String CHAR_ENCODING = "utf-8"

    static final int DEFAULT_TIMEOUT_MILLIS = 600000; // five minutes
    static final String DEFAULT_AUTH_HEADER = "X-ALA-userId"

    def grailsApplication
    AuthService authService

    /**
     * Sends an HTTP GET request to the specified URL. Any parameters must already be URL-encoded.
     *
     * @param url The url-encoded URL to send the request to
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map get(String url, boolean includeApiKey = true, boolean includeUser = true) {
        send(GET, url, null, null, includeApiKey, includeUser)
    }

    /**
     * Sends an HTTP PUT request to the specified URL.
     *
     * The data map will be sent as the JSON body of the request (i.e. use request.getJSON() on the receiving end).
     *
     * @param url The url-encoded url to send the request to
     * @param data Map containing the data to be sent as the post body
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map put(String url, Map data, boolean includeApiKey = true, boolean includeUser = true) {
        send(PUT, url, data, null, includeApiKey, includeUser)
    }

    /**
     * Sends an HTTP POST request to the specified URL.
     *
     * The data map will be sent as the JSON body of the request (i.e. use request.getJSON() on the receiving end).
     *
     * @param url The url-encoded url to send the request to
     * @param data Map containing the data to be sent as the post body
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map post(String url, Map data, boolean includeApiKey = true, boolean includeUser = true) {
        send(POST, url, data, null, includeApiKey, includeUser)
    }

    /**
     * Sends a multipart HTTP POST request to the specified URL.
     *
     * The data map will be sent as the JSON body of the request (i.e. use request.getJSON() on the receiving end).
     *
     * @param url The url-encoded url to send the request to
     * @param data Map containing the data to be sent as the post body
     * @param files List of 0 or more files to be included in the multipart request (note: if files is null, then the request will NOT be multipart)
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map postMultipart(String url, Map data, List files, boolean includeApiKey = true, boolean includeUser = true) {
        send(POST, url, data, files, includeApiKey, includeUser)
    }

    /**
     * Sends a HTTP DELETE request to the specified URL. Any parameters must already be URL-encoded.
     *
     * @param url The url-encoded url to send the request to
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map delete(String url, boolean includeApiKey = true, boolean includeUser = true) {
        send(DELETE, url, null, null, includeApiKey, includeUser)
    }

    /**
     * Proxies a request URL but doesn't assume the response is text based.
     *
     * Used for operations like proxying a download request from one application to another.
     *
     * @param response The HttpServletResponse of the calling request: the response from the proxied request will be written to this object
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @param url The URL of the service to proxy to
     */
    void proxyGetRequest(HttpServletResponse response, String url, boolean includeApiKey = true, boolean includeUser = true) {
        HttpURLConnection conn = (HttpURLConnection) configureConnection(url, includeApiKey, includeUser)
        conn.useCaches = false

        try {
            conn.setRequestProperty(CONNECTION, 'close') // disable Keep Alive

            conn.connect()

            response.contentType = conn.contentType
            int contentLength = conn.contentLength
            if (contentLength != -1) {
                response.contentLength = contentLength
            }

            List<String> headers = [CONTENT_DISPOSITION, TRANSFER_ENCODING]
            headers.each { header ->
                String headerValue = conn.getHeaderField(header)
                if (headerValue) {
                    response.setHeader(header, headerValue)
                }
            }
            response.status = conn.responseCode
            conn.inputStream.withStream { response.outputStream << it }
        } finally {
            conn.disconnect()
        }
    }

    private Map send(Method method, String url, Map data = null, List files = null, boolean includeApiKey = true, boolean includeUser = true) {
        log.debug("${method} request to ${url}")

        Map result = [:]

        try {
            HTTPBuilder http = new HTTPBuilder(url)

            http.request(method) { request ->
                configureRequestTimeouts(request)
                configureRequestHeaders(headers, includeApiKey, includeUser)

                if (files != null) {
                    request.entity = constructMultiPartEntity(data, files)
                } else if (data != null) {
                    contentType = ContentType.APPLICATION_JSON
                    body = data
                } else {
                    contentType = ContentType.APPLICATION_JSON
                }

                response.success = { resp, json ->
                    result.statusCode = resp.status
                    result.resp = json
                }
                response.failure = { resp ->
                    result.statusCode = resp.status
                    result.error = "Failed calling web service - service returned HTTP ${resp.status}"
                }

                result
            } as Map
        } catch (Exception e) {
            log.error("Failed sending ${method} request to ${url}", e)
            result.statusCode = HttpStatus.SC_INTERNAL_SERVER_ERROR
            result.error = "Failed calling web service. ${e.getClass()} ${e.getMessage()} URL= ${url}, method ${method}."
        }

        result
    }

    private String getApiKey() {
        grailsApplication.config.webservice.apiKey ?: null
    }

    private void configureRequestTimeouts(request) {
        int timeout = (grailsApplication.config.webservice.timeout ?: DEFAULT_TIMEOUT_MILLIS) as int

        RequestConfig.Builder config = RequestConfig.custom()
        config.setConnectTimeout(timeout)
        config.setSocketTimeout(timeout)
        config.setConnectionRequestTimeout(timeout)

        request?.config = config.build()
    }

    private void configureRequestHeaders(Map headers, boolean includeApiKey = true, boolean includeUser = true) {
        String apiKey = getApiKey()
        if (apiKey && includeApiKey) {
            headers.apiKey = apiKey
        }

        Map user = authService.userDetails()

        if (user && includeUser) {
            headers.put(grailsApplication.config.app?.http?.header?.userId ?: DEFAULT_AUTH_HEADER, user.userId as String)
            headers.put("Cookie", "ALA-Auth=${URLEncoder.encode(user.email, CHAR_ENCODING)}")
        }
    }

    private HttpEntity constructMultiPartEntity(Map data, List files) {
        MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create()
        entityBuilder.addPart("data", new StringBody((data as JSON) as String))
        files.eachWithIndex { it, index ->
            if (it instanceof byte[]) {
                entityBuilder.addPart("file${index}", new ByteArrayBody(it, "file${index}"))
            } else if (it instanceof CommonsMultipartFile) {
                entityBuilder.addPart(it.originalFilename, new ByteArrayBody(it.bytes, it.contentType, it.originalFilename))
            } else {
                entityBuilder.addPart("file${index}", new ByteArrayBody(it.bytes, "file${index}"))
            }
        }
        entityBuilder.build()
    }

    private URLConnection configureConnection(String url, boolean includeApiKey = true, boolean includeUser = true) {
        URLConnection conn = new URL(url).openConnection()

        conn.setConnectTimeout((grailsApplication.config.webservice?.timeout ?: DEFAULT_TIMEOUT_MILLIS) as int)
        conn.setReadTimeout((grailsApplication.config.webservice?.timeout ?: DEFAULT_TIMEOUT_MILLIS) as int)
        Map user = authService.userDetails()

        if (user && includeUser) {
            conn.setRequestProperty(grailsApplication.config.app?.http?.header?.userId as String, user.userId as String)
            conn.setRequestProperty("Cookie", "ALA-Auth=${URLEncoder.encode(user.userName, CHAR_ENCODING)}")
        }

        String apiKey = getApiKey()
        if (apiKey && includeApiKey) {
            conn.setRequestProperty("apiKey", apiKey)
        }

        conn
    }
}
