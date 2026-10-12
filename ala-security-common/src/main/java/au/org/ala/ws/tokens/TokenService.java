/*
 * Copyright (C) 2025 Atlas of Living Australia
 * All Rights Reserved.
 *
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 */

package au.org.ala.ws.tokens;

import com.google.common.annotations.VisibleForTesting;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.FrameworkParameters;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.context.session.SessionStoreFactory;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.factory.ProfileManagerFactory;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.JEEFrameworkParameters;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.OidcProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

public class TokenService {
    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    final boolean cacheTokens;

    final String clientId;
    final String clientSecret;

    final String jwtScopes;
    @VisibleForTesting
    final Object lock = new Object();
    private final OidcConfiguration oidcConfiguration;
    private final SessionStore sessionStore;
    private final SessionStoreFactory sessionStoreFactory;
    private final TokenClient tokenClient;
    private Object pac4jContextProvider;
    List<String> finalScopes;
    // mutable to break circular spring dependency
    Config config;
    final private long expiryWindow = 1; // 1 second
    private volatile transient OIDCTokens cachedCredentials;
    private volatile transient long cachedCredentialsLifetime = 0;

    /**
     * Legacy constructor supporting Pac4jContextProvider parameter for backwards compatibility.
     */
    @Deprecated
    public TokenService(Config config, OidcConfiguration oidcConfiguration, Object pac4jContextProvider,
                        SessionStoreFactory sessionStoreFactory, TokenClient tokenClient, String clientId,
                        String clientSecret, String jwtScopes, boolean cacheTokens) {
        this(oidcConfiguration, pac4jContextProvider, sessionStoreFactory, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens);
        this.config = config;
    }

    /**
     * Legacy constructor supporting Pac4jContextProvider parameter for backwards compatibility.
     */
    @Deprecated
    public TokenService(OidcConfiguration oidcConfiguration, Object pac4jContextProvider,
                        SessionStoreFactory sessionStoreFactory, TokenClient tokenClient, String clientId,
                        String clientSecret, String jwtScopes, boolean cacheTokens) {
        this(oidcConfiguration, sessionStoreFactory, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens);
        this.pac4jContextProvider = pac4jContextProvider;
    }

    public TokenService(Config config, OidcConfiguration oidcConfiguration, SessionStoreFactory sessionStoreFactory,
                        TokenClient tokenClient, String clientId, String clientSecret, String jwtScopes, boolean cacheTokens) {
        this(oidcConfiguration, sessionStoreFactory, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens);
        this.config = config;
    }

    public TokenService(Config config, OidcConfiguration oidcConfiguration, SessionStore sessionStore,
                        TokenClient tokenClient, String clientId, String clientSecret, String jwtScopes, boolean cacheTokens) {
        this(oidcConfiguration, sessionStore, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens);
        this.config = config;
    }

    public TokenService(OidcConfiguration oidcConfiguration, SessionStore sessionStore, TokenClient tokenClient,
                        String clientId, String clientSecret, String jwtScopes, boolean cacheTokens) {
        this(oidcConfiguration, sessionStore, null, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens);
    }

    public TokenService(OidcConfiguration oidcConfiguration, SessionStoreFactory sessionStoreFactory, TokenClient tokenClient,
                        String clientId, String clientSecret, String jwtScopes, boolean cacheTokens) {
        this(oidcConfiguration, null, sessionStoreFactory, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens);
    }

    private TokenService(OidcConfiguration oidcConfiguration, SessionStore sessionStore,
                         SessionStoreFactory sessionStoreFactory, TokenClient tokenClient,
                         String clientId, String clientSecret, String jwtScopes, boolean cacheTokens) {
        this.cacheTokens = cacheTokens;
        this.oidcConfiguration = oidcConfiguration;
        this.sessionStore = sessionStore;
        this.sessionStoreFactory = sessionStoreFactory;
        this.tokenClient = tokenClient;

        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.jwtScopes = jwtScopes;
        if (jwtScopes != null) {
            this.finalScopes = Arrays.stream(jwtScopes.split(" ")).filter(s -> !s.isEmpty()).toList();
        }
    }

    public ProfileManager getProfileManager() {
        HttpServletRequest request = resolveCurrentRequest();
        HttpServletResponse response = resolveCurrentResponse();
        return getProfileManager(request, response);
    }

    public ProfileManager getProfileManager(final HttpServletRequest request, final HttpServletResponse response) {
        WebContext context = null;
        FrameworkParameters params = null;
        if (pac4jContextProvider != null) {
            try {
                Method wcMethod = pac4jContextProvider.getClass().getMethod("webContext");
                context = (WebContext) wcMethod.invoke(pac4jContextProvider);
            } catch (Exception ignored) {
            }
            try {
                Method fpMethod = pac4jContextProvider.getClass().getMethod("frameworkParameters");
                params = (FrameworkParameters) fpMethod.invoke(pac4jContextProvider);
            } catch (Exception ignored) {
            }
        }

        if (context == null) {
            JEEFrameworkParameters jeeParams = new JEEFrameworkParameters(request, response);
            params = jeeParams;
            context = (config != null && config.getWebContextFactory() != null)
                    ? config.getWebContextFactory().newContext(jeeParams)
                    : JEEContextFactory.INSTANCE.newContext(jeeParams);
        }

        SessionStore resolvedSessionStore = this.sessionStore;
        if (resolvedSessionStore == null && this.sessionStoreFactory != null) {
            resolvedSessionStore = this.sessionStoreFactory.newSessionStore(params);
        }
        if (resolvedSessionStore == null && config != null && config.getSessionStoreFactory() != null) {
            resolvedSessionStore = config.getSessionStoreFactory().newSessionStore(params);
        }

        ProfileManagerFactory profileManagerFactory = config != null ? config.getProfileManagerFactory() : null;
        final ProfileManager manager = profileManagerFactory != null
                ? profileManagerFactory.apply(context, resolvedSessionStore)
                : new ProfileManager(context, resolvedSessionStore);
        if (config != null) {
            manager.setConfig(config);
        }
        return manager;
    }

    /**
     * Get an access token using current request context if available.
     *
     * @param requireUser Whether the auth token must belong to an individual user
     * @return The access token
     */
    public AccessToken getAuthToken(boolean requireUser) {
        HttpServletRequest req = resolveCurrentRequest();
        HttpServletResponse res = resolveCurrentResponse();
        return getAuthToken(requireUser, req, res);
    }

    /**
     * Get an access token. Will return the current user's access token or if there is no
     * current user, will request a client credentials grant based access token for this app.
     *
     * @param requireUser Whether the auth token must belong to an individual user
     * @param request The HTTP request
     * @param response The HTTP response
     * @return The access token
     */
    public AccessToken getAuthToken(boolean requireUser, final HttpServletRequest request, final HttpServletResponse response) {
        AccessToken token = null;
        if (requireUser) {
            token = getProfileManager(request, response).getProfile(OidcProfile.class).map(OidcProfile::getAccessToken).orElse(null);
        } else {
            if (oidcConfiguration != null) {
                OIDCTokens credentials;
                if (cacheTokens) {
                    credentials = getOrRefreshToken();
                } else {
                    credentials = clientCredentialsToken();
                }
                if (credentials != null) {
                    token = credentials.getAccessToken();
                }
            } else {
                log.debug("Not generating token because OIDC is not configured");
            }
        }
        return token;
    }

    private HttpServletRequest resolveCurrentRequest() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            try {
                Method getReq = attrs.getClass().getMethod("getRequest");
                Object req = getReq.invoke(attrs);
                if (req instanceof HttpServletRequest) {
                    return (HttpServletRequest) req;
                }
            } catch (Exception e) {
                log.trace("Could not resolve HttpServletRequest from RequestContextHolder: {}", e.getMessage());
            }
        }
        return null;
    }

    private HttpServletResponse resolveCurrentResponse() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            try {
                Method getRes = attrs.getClass().getMethod("getResponse");
                Object res = getRes.invoke(attrs);
                if (res instanceof HttpServletResponse) {
                    return (HttpServletResponse) res;
                }
            } catch (Exception e) {
                log.trace("Could not resolve HttpServletResponse from RequestContextHolder: {}", e.getMessage());
            }
        }
        return null;
    }

    private OIDCTokens getOrRefreshToken() {
        long now = (System.currentTimeMillis() / 1000) - expiryWindow;

        long lifetime = cachedCredentialsLifetime;
        if (lifetime == 0 || now >= lifetime) {
            synchronized (lock) {
                lifetime = cachedCredentialsLifetime;
                if (lifetime == 0 || now >= lifetime) {
                    OIDCTokens credentials = tokenSupplier(cachedCredentials);
                    cachedCredentials = credentials;
                    if (credentials != null && credentials.getAccessToken() != null) {
                        cachedCredentialsLifetime = (System.currentTimeMillis() / 1000) + credentials.getAccessToken().getLifetime();
                    }
                    return credentials;
                }
            }
        }
        return cachedCredentials;
    }

    private OIDCTokens tokenSupplier(OIDCTokens existingCredentials) {
        OIDCTokens credentials = null;
        if (existingCredentials != null && existingCredentials.getRefreshToken() != null) {
            try {
                log.debug("Refreshing existing token");
                credentials = refreshToken(existingCredentials.getRefreshToken());
            } catch (Exception e) {
                log.warn("Couldn't get refresh token from {}", existingCredentials.getRefreshToken(), e);
            }
        }
        if (credentials == null) {
            log.debug("Requesting new client credentials token");
            credentials = clientCredentialsToken();
        }
        return credentials;
    }

    private OIDCTokens clientCredentialsToken() {
        return sendTokenRequest(new ClientCredentialsGrant());
    }

    private OIDCTokens refreshToken(RefreshToken refreshToken) {
        return sendTokenRequest(new RefreshTokenGrant(refreshToken));
    }

    private OIDCTokens sendTokenRequest(AuthorizationGrant grant) {
        OIDCProviderMetadata metadata = oidcConfiguration.getOpMetadataResolver().load();
        ClientAuthentication clientAuthentication = getClientAuthentication(metadata);
        TokenRequest tokenRequest = new TokenRequest(
                metadata.getTokenEndpointURI(),
                clientAuthentication,
                grant,
                finalScopes != null ? new Scope(finalScopes.toArray(new String[0])) : new Scope()
        );
        try {
            return tokenClient.executeTokenRequest(tokenRequest);
        } catch (IOException | ParseException e) {
            log.error("failed to execute token request: " + e.getMessage(), e);
        }
        return null;
    }

    private ClientAuthentication getClientAuthentication(OIDCProviderMetadata metadata) {
        List<ClientAuthenticationMethod> methods = metadata.getTokenEndpointAuthMethods();
        if (methods == null || methods.isEmpty() || methods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            return new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
        } else if (methods.contains(ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
            return new ClientSecretPost(new ClientID(clientId), new Secret(clientSecret));
        } else {
            throw new UnsupportedOperationException("Unsupported token endpoint auth methods: " + methods);
        }
    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }
}
