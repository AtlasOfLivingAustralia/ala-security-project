package au.org.ala.web

import com.nimbusds.jwt.JWTParser
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils
import net.minidev.json.JSONObject
import net.minidev.json.parser.ParseException
import org.pac4j.core.adapter.FrameworkAdapter
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.context.session.SessionStoreFactory
import org.pac4j.core.profile.factory.ProfileManagerFactory
import org.pac4j.jee.config.AbstractConfigFilter
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.oidc.profile.OidcProfile

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class AffiliationSurveyFilter extends AbstractConfigFilter {

    WebContextFactory webContextFactory
    SessionStoreFactory sessionStoreFactory
    ProfileManagerFactory profileManagerFactory

    final Set<String> requiredScopesForAffiliationCheck// = ['ala', 'ala/attrs']
    final String affiliationAttribute// = 'affiliation'
    final String countryAttribute

    AffiliationSurveyFilter(Config config, SessionStoreFactory sessionStoreFactory, WebContextFactory webContextFactory, Set<String> requiredScopesForAffiliationCheck, String affiliationAttribute, String countryAttribute) {
        this.config = config
        this.sessionStoreFactory = sessionStoreFactory
        this.webContextFactory = webContextFactory
        this.requiredScopesForAffiliationCheck = requiredScopesForAffiliationCheck
        this.affiliationAttribute = affiliationAttribute
        this.countryAttribute = countryAttribute
    }

    @Override
    protected void internalFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        FrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config)

        def params = new JEEFrameworkParameters(request, response)
        def webContext = (this.webContextFactory ?: config.getWebContextFactory()).newContext(params)
        def sessionStore = (this.sessionStoreFactory ?: config.getSessionStoreFactory()).newSessionStore(params)
        def profileManager = (this.profileManagerFactory ?: config.getProfileManagerFactory()).apply(webContext, sessionStore)
        profileManager.setConfig(config)

        profileManager.getProfile().ifPresent {profile ->
            if (profile instanceof OidcProfile) {
                if (profile.accessToken.scope == null) {
                    introspectAccessToken(profile)
                }
                def scopeIncluded = requiredScopesForAffiliationCheck.any { requiredScope -> profile.accessToken.scope?.contains(requiredScope) }
                def missingAffiliationAttribute = !profile.containsAttribute(affiliationAttribute) || !profile.getAttribute(affiliationAttribute, String)
                def missingCountryAttribute = !profile.containsAttribute(countryAttribute) || !profile.getAttribute(countryAttribute, String)
                if (scopeIncluded && (missingAffiliationAttribute || missingCountryAttribute)) {
                    request.setAttribute('ala.affiliation-required', true)
                }
            }
        }
        chain.doFilter(request, response)
    }

    /**
     * Inspect and replace the profile's access token with the introspected version
     * // TODO Extract this somewhere more generically useful
     * @param profile
     * @return
     */
    private introspectAccessToken(OidcProfile profile) {
        // if JSON parse token
        JSONObject jsonObject
        try {
            def jwtClaimSet = JWTParser.parse(profile.accessToken.value).JWTClaimsSet.toJSONObject()
            jsonObject = new JSONObject(jwtClaimSet)
            def lifetime = parseExpiry(jsonObject)
            Scope scope = Scope.parse(JSONObjectUtils.getString(jsonObject, "scope", (String)null))
            profile.accessToken = new BearerAccessToken(profile.accessToken.value, lifetime, scope, profile.accessToken.issuedTokenType)
//            jsonObject = new JSONParser().parse(profile.accessToken.value)
        } catch (java.text.ParseException | ParseException e) {
            logger.debug('Could not parse access token')
            TokenIntrospectionRequest tir = new TokenIntrospectionRequest(''.toURI(), profile.accessToken)
            def tiResponse = TokenIntrospectionResponse.parse(tir.toHTTPRequest().send())
            if (tiResponse.indicatesSuccess()) {
                jsonObject = tiResponse.toSuccessResponse().toJSONObject()
                def lifetime = parseExpiry(jsonObject)
                Scope scope = Scope.parse(JSONObjectUtils.getString(jsonObject, "scope", (String)null))
                def token = AccessToken.parse(jsonObject)
                profile.accessToken = new BearerAccessToken(profile.accessToken.value, lifetime, scope, profile.accessToken.issuedTokenType)
            } else {
                logger.error('Failed to get token introspection', tiResponse.toErrorResponse().errorObject)
            }
        }
    }

    private parseExpiry(JSONObject object) {
        long lifetime
        if (object.containsKey("exp")) {
            if (object.get("exp") instanceof Number) {
                return JSONObjectUtils.getLong(object, "exp")
            } else {
                String lifetimeStr = JSONObjectUtils.getString(object, "exp")
                try {
                    return Long.parseLong(lifetimeStr)
                } catch (NumberFormatException var3) {
                    throw new java.text.ParseException("Invalid exp parameter, must be integer",0)
                }
            }
        } else {
            return 0L
        }
    }
}
