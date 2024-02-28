package au.org.ala.pac4j.core.logout;

import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.exception.http.ForbiddenAction;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.core.http.ajax.AjaxRequestResolver;
import org.pac4j.core.http.ajax.DefaultAjaxRequestResolver;
import org.pac4j.core.logout.LogoutActionBuilder;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.core.util.HttpActionHelper;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.OidcProfile;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Optional;

public class CognitoLogoutActionBuilder implements LogoutActionBuilder {

    protected OidcConfiguration configuration;

    private AjaxRequestResolver ajaxRequestResolver = new DefaultAjaxRequestResolver();

    public CognitoLogoutActionBuilder(final OidcConfiguration configuration) {
        CommonHelper.assertNotNull("configuration", configuration);
        this.configuration = configuration;
    }

    @Override
    public Optional<RedirectionAction> getLogoutAction(WebContext context, SessionStore sessionStore, UserProfile currentProfile, String targetUrl) {
        final var logoutUrl = configuration.findLogoutUrl();
        if (CommonHelper.isNotBlank(logoutUrl) && currentProfile instanceof OidcProfile) {
            try {
                final var completeLogoutUrl = UriComponentsBuilder.fromUriString(logoutUrl)
                        .queryParam("client_id", configuration.getClientId())
                        .queryParam("logout_uri", targetUrl)
                        .toUriString();

                if (ajaxRequestResolver.isAjax(context, sessionStore)) {
                    sessionStore.set(context, Pac4jConstants.REQUESTED_URL, null);
                    context.setResponseHeader(HttpConstants.LOCATION_HEADER, completeLogoutUrl);
                    throw new ForbiddenAction();
                }

                return Optional.of(HttpActionHelper.buildRedirectUrlAction(context, completeLogoutUrl));
            } catch (final RuntimeException e) {
                throw new TechnicalException(e);
            }
        }

        return Optional.empty();
    }

    public AjaxRequestResolver getAjaxRequestResolver() {
        return ajaxRequestResolver;
    }

    public void setAjaxRequestResolver(final AjaxRequestResolver ajaxRequestResolver) {
        CommonHelper.assertNotNull("ajaxRequestResolver", ajaxRequestResolver);
        this.ajaxRequestResolver = ajaxRequestResolver;
    }
}
