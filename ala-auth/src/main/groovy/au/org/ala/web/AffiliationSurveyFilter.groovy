package au.org.ala.web

import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContextFactory
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.profile.factory.ProfileManagerFactory
import org.pac4j.core.util.FindBest
import org.pac4j.jee.config.AbstractConfigFilter
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.oidc.profile.OidcProfile

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class AffiliationSurveyFilter extends AbstractConfigFilter {

    WebContextFactory webContextFactory
    SessionStore sessionStore
    ProfileManagerFactory profileManagerFactory

    final Set<String> requiredScopesForAffiliationCheck// = ['ala', 'ala/attrs']
    final String affiliationAttribute// = 'affiliation'

    AffiliationSurveyFilter(Config config, SessionStore sessionStore, WebContextFactory webContextFactory, Set<String> requiredScopesForAffiliationCheck, String affiliationAttribute) {
        this.config = config
        this.sessionStore = sessionStore
        this.webContextFactory = webContextFactory
        this.requiredScopesForAffiliationCheck = requiredScopesForAffiliationCheck
        this.affiliationAttribute = affiliationAttribute
    }

    @Override
    protected void internalFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        def webContext = FindBest.webContextFactory(this.webContextFactory, config, JEEContextFactory.INSTANCE).newContext(request, response)
        def sessionStore = FindBest.sessionStore(this.sessionStore, config, JEESessionStore.INSTANCE)
        def profileManager = FindBest.profileManagerFactory(this.profileManagerFactory, config, ProfileManagerFactory.DEFAULT).apply(webContext, sessionStore)
        profileManager.setConfig(config)

        profileManager.getProfile().ifPresent {profile ->
            if (profile instanceof OidcProfile) {
                def scopeIncluded = requiredScopesForAffiliationCheck.any { requiredScope -> profile.accessToken.scope.contains(requiredScope) }
                def missingAttribute = !profile.containsAttribute(affiliationAttribute) || !profile.getAttribute(affiliationAttribute, String)
                if (scopeIncluded && missingAttribute) {
                    request.setAttribute('ala.affiliation-required', true)
                }
            }
        }
    }

}
