package au.org.ala.ws.service

import au.org.ala.web.AuthService
import grails.converters.JSON
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.Method
import org.apache.http.HttpEntity
import org.apache.http.HttpStatus
import org.apache.http.client.config.RequestConfig
import org.apache.http.entity.ContentType
import org.apache.http.entity.mime.HttpMultipartMode
import org.apache.http.entity.mime.MultipartEntityBuilder
import org.apache.http.entity.mime.content.ByteArrayBody
import org.apache.http.entity.mime.content.FileBody
import org.apache.http.entity.mime.content.InputStreamBody
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
     * Sends an HTTP GET request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * @param url The url-encoded URL to send the request to
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param contentType the desired content type for the request. Defaults to application/json
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map get(String url, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true) {
        send(GET, url, params, contentType, null, null, includeApiKey, includeUser)
    }

    /**
     * Sends an HTTP PUT request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * The body map will be sent as the JSON body of the request (i.e. use request.getJSON() on the receiving end).
     *
     * @param url The url-encoded url to send the request to
     * @param body Map containing the data to be sent as the post body
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param contentType the desired content type for the request. Defaults to application/json
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map put(String url, Map body, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true) {
        send(PUT, url, params, contentType, body, null, includeApiKey, includeUser)
    }

    /**
     * Sends an HTTP POST request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * The body map will be sent as the body of the request (i.e. use request.getJSON() on the receiving end).
     *
     * @param url The url-encoded url to send the request to
     * @param body Map containing the data to be sent as the post body
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param contentType the desired content type for the request. Defaults to application/json
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map post(String url, Map body, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true) {
        send(POST, url, params, contentType, body, null, includeApiKey, includeUser)
    }

    /**
     * Sends a multipart HTTP POST request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * Each item in the body map will be sent as a separate Part in the Multipart Request. To send the entire map as a
     * single part, you will need too use the format [data: body].
     *
     * Files can be one of the following types:
     * <ul>
     * <li>byte[]</li>
     * <li>CommonsMultipartFile</li>
     * <li>InputStream</li>
     * <li>File</li>
     * <li>Anything that supports the .bytes accessor</li>
     * </ul>
     *
     * @param url The url-encoded url to send the request to
     * @param body Map containing the data to be sent as the post body
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param files List of 0 or more files to be included in the multipart request (note: if files is null, then the request will NOT be multipart)
     * @param partContentType the desired content type for the request PARTS (the request itself will always be sent as multipart/form-data). Defaults to application/json. All non-file parts will have the same content type.
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map postMultipart(String url, Map body, Map params = [:], List files = [], ContentType partContentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true) {
        send(POST, url, params, partContentType, body, files, includeApiKey, includeUser)
    }

    /**
     * Sends a HTTP DELETE request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * @param url The url-encoded url to send the request to
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param contentType the desired content type for the request. Defaults to application/json
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map delete(String url, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true) {
        send(DELETE, url, params, contentType, null, null, includeApiKey, includeUser)
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

    private Map send(Method method, String url, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, Map body = null, List files = null, boolean includeApiKey = true, boolean includeUser = true) {
        log.debug("${method} request to ${url}")

        Map result = [:]

        try {
            url = appendQueryString(url, params)
            HTTPBuilder http = new HTTPBuilder(url, contentType)

            http.request(method, contentType) { request ->
                configureRequestTimeouts(request)
                configureRequestHeaders(headers, includeApiKey, includeUser)

                if (files != null) {
                    // NOTE: order is important - Content-Type MUST be set BEFORE the body
                    request.entity = constructMultiPartEntity(body, files, contentType)
                } else if (body != null) {
                    // NOTE: order is important - Content-Type MUST be set BEFORE the body
                    delegate.contentType = contentType
                    delegate.body = body
                }

                response.success = { resp, data ->
                    result.statusCode = resp.status
                    if (data instanceof InputStreamReader) {
                        result.resp = data.text
                    } else {
                        result.resp = data
                    }
                }
                response.failure = { resp ->
                    result.statusCode = resp.status
                    result.error = "Failed calling web service - service returned HTTP ${resp.status}"
                }

                result
            } as Map
        } catch (Exception e) {
            e.printStackTrace()
            log.error("Failed sending ${method} request to ${url}", e)
            result.statusCode = HttpStatus.SC_INTERNAL_SERVER_ERROR
            result.error = "Failed calling web service. ${e.getClass()} ${e.getMessage()} URL= ${url}, method ${method}."
        }

        result
    }

    private String appendQueryString(String url, Map params) {
        if (params) {
            url += url.contains("?") ? '&' : '?'

            def enc = { str -> URLEncoder.encode(str, CHAR_ENCODING) }

            url += params.inject([]) { result, entry ->
                result << "${enc(entry.key)}=${enc(entry.value?.toString())}"
            }?.join("&")
        }

        url
    }

    private String getApiKey() {
        grailsApplication.config.webservice.apiKey ?: null
    }

    private void configureRequestTimeouts(request) {
        int connectTimeout = (grailsApplication.config.webservice?.connect?.timeout ?: DEFAULT_TIMEOUT_MILLIS) as int
        int readTimeout = (grailsApplication.config.webservice?.read?.timeout ?: DEFAULT_TIMEOUT_MILLIS) as int
        int socketTimeout = (grailsApplication.config.webservice?.socket?.timeout ?: DEFAULT_TIMEOUT_MILLIS) as int

        RequestConfig.Builder config = RequestConfig.custom()
        config.setConnectTimeout(connectTimeout)
        config.setSocketTimeout(socketTimeout)
        config.setConnectionRequestTimeout(readTimeout)

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

    private HttpEntity constructMultiPartEntity(Map parts, List files, ContentType partContentType = ContentType.APPLICATION_JSON) {
        MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create()
        entityBuilder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE)

        parts?.each { key, value ->
            def val = partContentType == ContentType.APPLICATION_JSON && !(value instanceof net.sf.json.JSON) ? value as JSON : value
            entityBuilder.addPart(key?.toString(), new StringBody((val) as String, partContentType))
        }

        files.eachWithIndex { it, index ->
            if (it instanceof byte[]) {
                entityBuilder.addPart("file${index}", new ByteArrayBody(it, "file${index}"))
            } else if (it instanceof CommonsMultipartFile) {
                entityBuilder.addPart(it.originalFilename, new InputStreamBody(it.inputStream, it.contentType, it.originalFilename))
            } else if (it instanceof InputStream) {
                entityBuilder.addPart("file${index}", new InputStreamBody(it, "file${index}"))
            }  else if (it instanceof File) {
                entityBuilder.addPart(it.getName(), new FileBody(it, it.getName()))
            } else {
                entityBuilder.addPart("file${index}", new ByteArrayBody(it.bytes, "file${index}"))
            }
        }
        entityBuilder.build()
    }

    private URLConnection configureConnection(String url, boolean includeApiKey = true, boolean includeUser = true) {
        URLConnection conn = new URL(url).openConnection()

        conn.setConnectTimeout((grailsApplication.config.webservice?.connect?.timeout ?: DEFAULT_TIMEOUT_MILLIS) as int)
        conn.setReadTimeout((grailsApplication.config.webservice?.read?.timeout ?: DEFAULT_TIMEOUT_MILLIS) as int)
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
