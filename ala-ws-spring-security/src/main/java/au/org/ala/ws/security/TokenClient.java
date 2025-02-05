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

package au.org.ala.ws.security;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

// TODO: move this and related classes into ala-security-project
public class TokenClient {
    private static final Logger logger = LoggerFactory.getLogger(TokenClient.class);

    final private OidcConfiguration oidcConfiguration;

    public TokenClient(OidcConfiguration oidcConfiguration) {
        this.oidcConfiguration = oidcConfiguration;
    }


    public OidcCredentials executeTokenRequest(TokenRequest request) throws IOException, ParseException {
        HTTPRequest tokenHttpRequest = request.toHTTPRequest();
        if (oidcConfiguration != null) {
            oidcConfiguration.configureHttpRequest(tokenHttpRequest);
        }

        HTTPResponse httpResponse = tokenHttpRequest.send();
        logger.debug("Token response: status={}, content={}", httpResponse.getStatusCode(),
                httpResponse.getContent());

        TokenResponse response = OIDCTokenResponseParser.parse(httpResponse);
        if (response instanceof TokenErrorResponse) {
            ErrorObject errorObject = ((TokenErrorResponse) response).getErrorObject();
            throw new TechnicalException("Bad token response, error=" + errorObject.getCode() + "," +
                    " description=" + errorObject.getDescription());
        }
        logger.debug("Token response successful");
        OIDCTokenResponse tokenSuccessResponse = (OIDCTokenResponse) response;

        OidcCredentials credentials = new OidcCredentials();
        OIDCTokens oidcTokens = tokenSuccessResponse.getOIDCTokens();
        credentials.setAccessToken(oidcTokens.getAccessToken());
        credentials.setRefreshToken(oidcTokens.getRefreshToken());
        if (oidcTokens.getIDToken() != null) {
            credentials.setIdToken(oidcTokens.getIDToken());
        }
        return credentials;
    }
}
