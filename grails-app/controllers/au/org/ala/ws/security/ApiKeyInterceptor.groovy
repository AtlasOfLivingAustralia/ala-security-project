package au.org.ala.ws.security

import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.org.ala.ws.security.service.ApiKeyService
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.grails.web.util.WebUtils
import org.pac4j.core.config.Config
import org.pac4j.core.context.JEEContextFactory
import org.pac4j.core.context.WebContext
import org.pac4j.core.credentials.extractor.BearerAuthExtractor
import org.pac4j.core.credentials.extractor.HeaderExtractor
import org.pac4j.core.profile.ProfileManager
import org.pac4j.core.profile.factory.ProfileManagerFactory
import org.pac4j.core.profile.factory.ProfileManagerFactoryAware
import org.pac4j.core.util.FindBest
import org.pac4j.core.util.Pac4jConstants
import org.pac4j.jwt.config.encryption.RSAEncryptionConfiguration
import org.pac4j.jwt.config.signature.ECSignatureConfiguration
import org.pac4j.jwt.config.signature.RSASignatureConfiguration
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration
import org.pac4j.jwt.config.signature.SignatureConfiguration
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator
import org.pac4j.oidc.config.OidcConfiguration
import org.springframework.beans.factory.annotation.Autowired

import javax.servlet.http.HttpServletRequest

@CompileStatic
@Slf4j
class ApiKeyInterceptor {
    ApiKeyService apiKeyService

    static final int STATUS_UNAUTHORISED = 403
    static final String API_KEY_HEADER_NAME = "apiKey"
    static final List<String> LOOPBACK_ADDRESSES = ["127.0.0.1",
                                                    "0:0:0:0:0:0:0:1", // IP v6
                                                    "::1"] // IP v6 short form
    @Autowired(required = false)
    Config config

    ApiKeyInterceptor() {
        matchAll()
    }

    /**
     * Executed before a matched action
     *
     * @return Whether the action should continue and execute
     */
    boolean before() {
        def controller = grailsApplication.getArtefactByLogicalPropertyName("Controller", controllerName)
        Class controllerClass = controller?.clazz
        def method = controllerClass?.getMethod(actionName ?: "index", [] as Class[])

        def result = true
        if ((controllerClass?.isAnnotationPresent(RequireApiKey) && !method?.isAnnotationPresent(SkipApiKeyCheck))
                || method?.isAnnotationPresent(RequireApiKey)) {
            def annotation = method?.getAnnotation(RequireApiKey) ?: controllerClass?.getAnnotation(RequireApiKey)
            if (grailsApplication.config.getProperty('security.oidc.enabled', Boolean, true)) {
                result = oidcApiKeyInterceptor(annotation as RequireApiKey)
            } else {
                result = legacyApiKeyInterceptor()
            }
        }
        return result
    }

    /**
     * Executed after the action executes but prior to view rendering
     *
     * @return True if view rendering should continue, false otherwise
     */
    boolean after() { true }

    /**
     * Executed after view rendering completes
     */
    void afterView() {}

    boolean oidcApiKeyInterceptor(RequireApiKey requireApiKey) {
        def result = false
        if (config instanceof OidcConfiguration) {
            def metadata = (config as OidcConfiguration).findProviderMetadata()
            JwtAuthenticator jwtAuthenticator = getJwtAuthenticator(metadata)
            BearerAuthExtractor bearerAuthExtractor = new BearerAuthExtractor()
            def context = context()
            ProfileManager profileManager = new ProfileManager(context, config.sessionStore)
            def credentials = bearerAuthExtractor.extract(context, config.sessionStore)
            if (credentials.isPresent()) {
                def creds = credentials.get()
                try {
                    jwtAuthenticator.validate(creds, context, config.sessionStore)

                    def userProfile = creds.userProfile

                    if (userProfile) {
                        profileManager.save(false, creds.userProfile, false)
                    }

                    if (requireApiKey.scopes()) {
                        def scope = userProfile.attributes['scope'] as List<String>
                        result = requireApiKey.scopes().every {
                            scope.contains(it)
                        }
                    } else {
                        result = true
                    }

                } catch (e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Couldn't validate JWT", e)
                    } else {
                        log.info("Couldn't validate JWT: {}", e.message)
                    }
                    result = false
                }
            }
        }
        return result
    }

    /**
     * Configure a JWT authenticator based on OIDC metadata.
     * TODO extract this so that it can mocked for testing.
     * @param metadata The OIDC metadata
     * @return A JwtAuthenticator configured from the JWKSet in the metadata
     */
    private JwtAuthenticator getJwtAuthenticator(OIDCProviderMetadata metadata) {
        def jwkset = JWKSet.load(metadata.JWKSetURI.toURL())

        def signatureConfigs = []
        def encryptConfigs = []

        jwkset.keys.each { jwk ->
            def algo = jwk.algorithm
            switch (algo) {
                case JWSAlgorithm:
                    def signatureConfig
                    if (JWSAlgorithm.Family.RSA.contains(algo)) {
                        signatureConfig = new RSASignatureConfiguration(jwk.toRSAKey().toKeyPair(), (JWSAlgorithm) algo)
                    } else if (JWSAlgorithm.Family.EC.contains(algo)) {
                        signatureConfig = new ECSignatureConfiguration(jwk.toECKey().toKeyPair(), (JWSAlgorithm) algo)
                    } else if (JWSAlgorithm.Family.HMAC_SHA.contains(algo)) {
                        // TODO This should never hit?  Provide HMAC password via config instead?
                        signatureConfig = new SecretSignatureConfiguration(jwk.toOctetSequenceKey().toByteArray(), (JWSAlgorithm) algo)
                    }
                    if (signatureConfig) {
                        signatureConfigs.add(signatureConfig)
                    }
                    break
                    // TODO JWT Encryption
//                    case JWEAlgorithm:
//                        def encryptionConfig
//                        if (JWEAlgorithm.Family.RSA.contains(algo)) {
//                            encryptionConfig = new RSAEncryptionConfiguration(jwk.toRSAKey().toKeyPair(), (JWEAlgorithm)algo, null)
//                        }
//                    case EncryptionMethod:
            }

        }

        return new JwtAuthenticator(signatureConfigs, encryptConfigs)
    }

    def context() {
        def gwr = WebUtils.retrieveGrailsWebRequest()
        def request = gwr.request
        def response = gwr.response
        final WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)
        return context
    }

    boolean legacyApiKeyInterceptor() {
        List<String> whiteList = buildWhiteList()
        String clientIp = getClientIP(request)
        boolean ipOk = checkClientIp(clientIp, whiteList)
        def result = true
        if (!ipOk) {
            String headerName = grailsApplication.config.navigate('security', 'apikey', 'header', 'override') ?: API_KEY_HEADER_NAME
            boolean keyOk = apiKeyService.checkApiKey(request.getHeader(headerName)).valid
            log.debug "IP ${clientIp} ${ipOk ? 'is' : 'is not'} ok. Key ${keyOk ? 'is' : 'is not'} ok."

            if (!keyOk) {
                log.warn(ipOk ? "No valid api key for ${controllerName}/${actionName}" :
                        "Non-authorised IP address - ${clientIp}")
                response.status = STATUS_UNAUTHORISED
                response.sendError(STATUS_UNAUTHORISED, "Forbidden")
                result = false
            }
        } else {
            log.debug("IP ${clientIp} is exempt from the API Key check. Authorising.")
        }
        return result
    }

    /**
     * Client IP passes if it is in the whitelist
     * @param clientIp
     * @return
     */
    def checkClientIp(clientIp, List<String> whiteList) {
        whiteList.contains(clientIp)
    }

    List<String> buildWhiteList() {
        List<String> whiteList = []
        whiteList.addAll(LOOPBACK_ADDRESSES) // allow calls from localhost to make testing easier
        String config = grailsApplication.config.navigate('security', 'apikey', 'ip', 'whitelist')
        if (config) {
            whiteList.addAll(config.split(',').collect({ String s -> s.trim() }))
        }
        log.debug('{}', whiteList)
        return whiteList
    }

    def getClientIP(HttpServletRequest request) {
        // External requests may be proxied by Apache, which uses X-Forwarded-For to identify the original IP.
        String ip = request.getHeader("X-Forwarded-For")
        if (!ip || LOOPBACK_ADDRESSES.contains(ip)) {
            // don't accept localhost from the X-Forwarded-For header, since it can be easily spoofed.
            ip = request.getRemoteHost()
        }
        return ip
    }

}
