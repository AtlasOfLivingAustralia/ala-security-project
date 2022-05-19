package au.org.ala.ws.service

import au.org.ala.web.AuthService
import au.org.ala.web.UserDetails
import com.google.common.net.HttpHeaders
import grails.converters.JSON
import groovyx.net.http.ContentType as GContentType
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.Method
import groovyx.net.http.ParserRegistry
import org.apache.http.HttpEntity
import org.apache.http.HttpResponse
import org.apache.http.HttpStatus
import org.apache.http.client.config.RequestConfig
import org.apache.http.entity.AbstractHttpEntity
import org.apache.http.entity.ContentType
import org.apache.http.entity.StringEntity
import org.apache.http.entity.mime.HttpMultipartMode
import org.apache.http.entity.mime.MultipartEntityBuilder
import org.apache.http.entity.mime.content.ByteArrayBody
import org.apache.http.entity.mime.content.FileBody
import org.apache.http.entity.mime.content.InputStreamBody
import org.apache.http.entity.mime.content.StringBody
import org.grails.web.json.JSONElement
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.multipart.MultipartFile

import javax.servlet.http.HttpServletResponse
import java.nio.charset.Charset

import static grails.web.http.HttpHeaders.AUTHORIZATION
import static grails.web.http.HttpHeaders.CONNECTION
import static grails.web.http.HttpHeaders.CONTENT_DISPOSITION
import static groovyx.net.http.Method.*

class WebService {
    static final String CHAR_ENCODING = "UTF-8"
    static final Charset UTF_8 = Charset.forName(CHAR_ENCODING)

    static final int DEFAULT_TIMEOUT_MILLIS = 600000 // five minutes
    static final String DEFAULT_AUTH_HEADER = "X-ALA-userId"
    static final String DEFAULT_API_KEY_HEADER = "apiKey"

    static {
        ParserRegistry.setDefaultCharset(CHAR_ENCODING)
    }

    def grailsApplication
    AuthService authService
    JwtTokenService jwtTokenService

    /**
     * Sends an HTTP GET request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * Note: by default, the Accept header will be set to the same content type as the ContentType provided. To override
     * this default behaviour, include an 'Accept' header in the 'customHeaders' parameter.
     *
     * @param url The url-encoded URL to send the request to
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param contentType the desired content type for the request. Defaults to application/json
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @param customHeaders Map of [headerName:value] for any extra HTTP headers to be sent with the request. Default = [:].
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map get(String url, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true, Map customHeaders = [:]) {
        send(GET, url, params, contentType, null, null, includeApiKey, includeUser, customHeaders)
    }

    /**
     * Sends an HTTP PUT request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * Note: by default, the Accept header will be set to the same content type as the ContentType provided. To override
     * this default behaviour, include an 'Accept' header in the 'customHeaders' parameter.
     *
     * The body map will be sent as the JSON body of the request (i.e. use request.getJSON() on the receiving end).
     *
     * @param url The url-encoded url to send the request to
     * @param body Map containing the data to be sent as the post body
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param contentType the desired content type for the request. Defaults to application/json
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @param customHeaders Map of [headerName:value] for any extra HTTP headers to be sent with the request. Default = [:].
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map put(String url, Map body, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true, Map customHeaders = [:]) {
        send(PUT, url, params, contentType, body, null, includeApiKey, includeUser, customHeaders)
    }

    /**
     * Sends an HTTP POST request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * Note: by default, the Accept header will be set to the same content type as the ContentType provided. To override
     * this default behaviour, include an 'Accept' header in the 'customHeaders' parameter.
     *
     * The body map will be sent as the body of the request (i.e. use request.getJSON() on the receiving end).
     *
     * @param url The url-encoded url to send the request to
     * @param body Map containing the data to be sent as the post body
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param contentType the desired content type for the request. Defaults to application/json
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @param customHeaders Map of [headerName:value] for any extra HTTP headers to be sent with the request. Default = [:].
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map post(String url, Map body, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true, Map customHeaders = [:]) {
        send(POST, url, params, contentType, body, null, includeApiKey, includeUser, customHeaders)
    }

    /**
     * Sends a multipart HTTP POST request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * Note: by default, the Accept header will be set to the same content type as the ContentType provided. To override
     * this default behaviour, include an 'Accept' header in the 'customHeaders' parameter.
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
     * @param customHeaders Map of [headerName:value] for any extra HTTP headers to be sent with the request. Default = [:].
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map postMultipart(String url, Map body, Map params = [:], List files = [], ContentType partContentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true, Map customHeaders = [:]) {
        send(POST, url, params, partContentType, body, files, includeApiKey, includeUser, customHeaders)
    }

    /**
     * Sends a HTTP DELETE request to the specified URL. The URL must already be URL-encoded (if necessary).
     *
     * Note: by default, the Accept header will be set to the same content type as the ContentType provided. To override
     * this default behaviour, include an 'Accept' header in the 'customHeaders' parameter.
     *
     * @param url The url-encoded url to send the request to
     * @param params Map of parameters to be appended to the query string. Parameters will be URL-encoded automatically.
     * @param contentType the desired content type for the request. Defaults to application/json
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     * @param customHeaders Map of [headerName:value] for any extra HTTP headers to be sent with the request. Default = [:].
     * @return [statusCode: int, resp: [:]] on success, or [statusCode: int, error: string] on error
     */
    Map delete(String url, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = true, boolean includeUser = true, Map customHeaders = [:]) {
        send(DELETE, url, params, contentType, null, null, includeApiKey, includeUser, customHeaders)
    }

    /**
     * Proxies a request URL but doesn't assume the response is text based.
     *
     * Used for operations like proxying a download request from one application to another.
     *
     * @param response The HttpServletResponse of the calling request: the response from the proxied request will be written to this object
     * @param url The URL of the service to proxy to
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     */
    void proxyGetRequest(HttpServletResponse response, String url, boolean includeApiKey = true, boolean includeUser = true) {
        log.debug("Proxying GET request to ${url}")
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

            List<String> headers = [CONTENT_DISPOSITION]
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

    /**
     * Proxies a request URL with post data but doesn't assume the response is text based.
     *
     * @param response The HttpServletResponse of the calling request: the response from the proxied request will be written to this object
     * @param url The URL of the service to proxy to
     * @param postBody The POST data to send with the proxied request. If it is a Collection, then it will be converted to JSON, otherwise it will be sent as a String.
     * @param contentType the desired content type for the request. Defaults to application/json.
     * @param includeApiKey true to include the service's API Key in the request headers (uses property 'service.apiKey'). Default = true.
     * @param includeUser true to include the userId and email in the request headers and the ALA-Auth cookie. Default = true.
     */
    void proxyPostRequest(HttpServletResponse response, String url, postBody, ContentType contentType = ContentType.APPLICATION_JSON, boolean includeApiKey = false, boolean includeUser = true, Map cookies = [:]) {
        log.debug("Proxying POST request to ${url}")

        HttpURLConnection conn = (HttpURLConnection) configureConnection(url, includeApiKey, includeUser)
        conn.useCaches = false

        try {
            conn.setRequestMethod("POST")
            conn.setRequestProperty(CONNECTION, 'close') // disable Keep Alive
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", contentType.toString());

            cookies?.each { cookie, value ->
                conn.setRequestProperty(cookie, value)
            }

            OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream(), CHAR_ENCODING)
            if (contentType == ContentType.APPLICATION_JSON && postBody instanceof Collection) {
                wr.write((postBody as JSON).toString())
            } else if (contentType == ContentType.APPLICATION_FORM_URLENCODED) {
                String formData = postBody.inject([]) { result, entry ->
                    if (entry.value instanceof Collection || entry.value instanceof String[]) {
                        result << "${enc(entry.key)}=${enc(entry.value?.join(","))}"
                    } else {
                        result << "${enc(entry.key)}=${enc(entry.value?.toString())}"
                    }
                }?.join("&")
                wr.write(formData)
            } else {
                wr.write(postBody?.toString())
            }
            wr.flush()
            wr.close()

            response.contentType = conn.contentType
            int contentLength = conn.contentLength
            if (contentLength != -1) {
                response.contentLength = contentLength
            }

            List<String> headers = [CONTENT_DISPOSITION]
            headers.each { header ->
                String headerValue = conn.getHeaderField(header)
                if (headerValue) {
                    response.setHeader(header, headerValue)
                }
            }
            response.status = conn.responseCode
            response.outputStream << conn.inputStream
        } finally {
            conn.disconnect()
        }
    }

    private Map send(Method method, String url, Map params = [:], ContentType contentType = ContentType.APPLICATION_JSON,
                     Map body = null, List files = null, boolean includeApiKey = true, boolean includeUser = true,
                     Map customHeaders = [:]) {
        log.debug("${method} request to ${url}")

        Map result = [:]

        try {
            url = appendQueryString(url, params)

            HTTPBuilder http = newHttpBuilder(url, contentType)

            http.request(method, contentType) { request ->
                configureRequestTimeouts(request)
                configureRequestHeaders(headers, includeApiKey, includeUser, customHeaders)

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
                    } else if (data instanceof List) {
                        // ensure an empty list is not converted to an empty object
                        result.resp = data
                    } else {
                        result.resp = data ?: [:]
                    }
                }
                response.failure = { resp ->
                    log.error("Request failed with response: ${resp?.entity?.content?.text}")
                    result.statusCode = resp.status
                    result.error = "Failed calling web service - service returned HTTP ${resp.status}"
                }
            }
        } catch (Exception e) {
            e.printStackTrace()
            log.error("Failed sending ${method} request to ${url}", e)
            result.statusCode = HttpStatus.SC_INTERNAL_SERVER_ERROR
            result.error = "Failed calling web service. ${e.getClass()} ${e.getMessage()} URL= ${url}, method ${method}."
        }

        result
    }

    HTTPBuilder newHttpBuilder(String url, ContentType contentType) {
        HTTPBuilder http = new HTTPBuilder(url, contentType)
        // Since we're in a Grails context, let's use Grails JSON for encoding and decoding
        final encoder = WebService.&encodeJSON
        final decoder = WebService.&decodeJSON
        http.encoder[GContentType.JSON] = encoder
        http.encoder[ContentType.APPLICATION_JSON] = encoder
        http.parser[GContentType.JSON] = decoder
        http.parser[ContentType.APPLICATION_JSON] = decoder
        // TODO XML
        return http
    }

    private static String appendQueryString(String url, Map params) {
        if (params) {
            url += url.contains("?") ? '&' : '?'


            url += params.inject([]) { result, entry ->
                result << "${enc(entry.key)}=${enc(entry.value?.toString())}"
            }?.join("&")
        }

        url
    }

    private String getApiKey() {
        grailsApplication.config.webservice.apiKey ?: null
    }

    static String enc(String str) {
        str ? URLEncoder.encode(str, CHAR_ENCODING) : ""
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

    private void configureRequestHeaders(Map headers, boolean includeApiKey = true, boolean includeUser = true, Map customHeaders = [:]) {

        UserDetails user
        // We can only get the user id from the auth service if we are running in a http request.
        // The Sprint RequestContextHolder's requestAttributes will be null if there is no request.
        // The #currentRequestAttributes method, which is used by the authService, throws an IllegalStateException if
        // there is no request, so we need to check if requestAttributes exist before trying to get the user details.
        if (includeUser && RequestContextHolder.getRequestAttributes() != null) {
            user = authService.userDetails()
        }

        def userAgent = getUserAgent()
        if (userAgent) {
            headers.put(HttpHeaders.USER_AGENT, userAgent)
        }

        includeAuthTokensInternal(includeUser, includeApiKey, user) { key, value ->
            headers.put(key, value)
        }

        if (customHeaders) {
            headers.putAll(customHeaders)
        }
    }

    private static HttpEntity constructMultiPartEntity(Map parts, List files, ContentType partContentType = ContentType.APPLICATION_JSON) {
        MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create()
        entityBuilder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE)

        parts?.each { key, value ->
            def val = partContentType == ContentType.APPLICATION_JSON && !(value instanceof net.sf.json.JSON) ? value as JSON : value
            entityBuilder.addPart(key?.toString(), new StringBody((val) as String, partContentType))
        }

        files.eachWithIndex { it, index ->
            if (it instanceof byte[]) {
                entityBuilder.addPart("file${index}", new ByteArrayBody(it, "file${index}"))
            }
            // Grails 3.3 multipart file is instance of org.springframework.web.multipart.support.StandardMultipartHttpServletRequest.StandardMultipartFile
            // But StandardMultipartFile and CommonMultipartFile are both inherited from MultipartFile
            else if (it instanceof MultipartFile) {
                entityBuilder.addPart(it.originalFilename, new InputStreamBody(it.inputStream, it.contentType, it.originalFilename))
            } else if (it instanceof InputStream) {
                entityBuilder.addPart("file${index}", new InputStreamBody(it, "file${index}"))
            } else if (it instanceof File) {
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
        def userAgent = getUserAgent()
        if (userAgent) {
            conn.setRequestProperty(HttpHeaders.USER_AGENT, userAgent)
        }
        def user = authService.userDetails()

        includeAuthTokens(includeUser, includeApiKey, user, conn)

        conn
    }

    void includeAuthTokens(Boolean includeUser, Boolean includeApiKey, UserDetails user, URLConnection conn) {
        includeAuthTokensInternal(includeUser, includeApiKey, user) { key, value ->
            conn.setRequestProperty(key, value)
        }
    }

    private void includeAuthTokensInternal(Boolean includeUser, Boolean includeApiKey, UserDetails user, Closure<Void> headerSetter) {
        if (grailsApplication.config.getProperty('webservice.jwt', Boolean, false)) {
            includeAuthTokensJwt(includeUser, includeApiKey, user, headerSetter)
        } else {
            includeAuthTokensLegacy(includeUser, includeApiKey, user, headerSetter)
        }
    }

    void includeAuthTokensJwt(includeUser, includeApiKey, user, headerSetter) {
        if ((user && includeUser) || (apiKey && includeApiKey)) {
            def token = jwtTokenService.getAuthToken(false) // TODO use includeUser here?
            if (token) {
                headerSetter(AUTHORIZATION, token.toAuthorizationHeader())
            }
        }
    }

    void includeAuthTokensLegacy(includeUser, includeApiKey, user, headerSetter) {
        if ((user && includeUser)) {
            headerSetter((grailsApplication.config.app?.http?.header?.userId ?: DEFAULT_AUTH_HEADER) as String, user.userId as String)
            headerSetter("Cookie", "ALA-Auth=${URLEncoder.encode(user.userName ?: "", CHAR_ENCODING)}")
            headerSetter("ALA-Auth", "${URLEncoder.encode(user.userName ?: "", CHAR_ENCODING)}")
        }

        String apiKey = getApiKey()
        if (apiKey && includeApiKey) {
            headerSetter("apiKey", apiKey)
        }
    }

    private String getUserAgent() {
        def name = grailsApplication.config.getProperty('info.app.name', String)
        def version = grailsApplication.config.getProperty('info.app.version', String)
        if (name && version) {
            return "$name/$version"
        } else {
            return ''
        }
    }

    /**
     * Use Grails JSON to encode an object as JSON.  If the object is a String, assume that it's
     * already a well formed JSON document and return it as such.  Otherwise, convert the object
     * to JSON using `o as JSON` and then return an entity that will write the result to an OutputStream.
     *
     * @param model The model to convert to JSON
     * @param contentType The content type.  Could be anything.
     * @return The HTTP Entity that will write the model to an outputstream as JSON
     */
    static HttpEntity encodeJSON(Object model, Object contentType) {
//        log.info("Grails encodeJSON")
        final entity
        if (model instanceof String) {
            entity = new StringEntity( model, contentType.toString(), CHAR_ENCODING )
        } else {
            final json = model as JSON
            entity = new AbstractHttpEntity() {
                @Override
                boolean isRepeatable() {
                    false
                }

                @Override
                long getContentLength() {
                    -1
                }

                @Override
                InputStream getContent() throws IOException, IllegalStateException {
                    throw new UnsupportedOperationException('This entity only supports writing')
                }

                @Override
                void writeTo(OutputStream outputStream) throws IOException {
                    OutputStreamWriter w = new OutputStreamWriter(outputStream, UTF_8)
                    json.render(w)
                }

                @Override
                boolean isStreaming() {
                    false
                }
            }
        }
        entity.setContentType( contentType.toString() )
        return entity
    }

    /**
     * Decode an Apache HTTP Response as JSON using the Grails JSON support
     *
     * @param httpResponse The HTTP Response to decode as JSON
     * @return A Grails JSONElement
     */
    static JSONElement decodeJSON(HttpResponse httpResponse) {
//        log.info("Grails decodeJSON")
        final cs = ParserRegistry.getCharset(httpResponse)
        def json = JSON.parse(new InputStreamReader(httpResponse.entity.content, cs))
        return json
    }
}
