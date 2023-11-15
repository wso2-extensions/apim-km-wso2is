/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is.key.manager.tokenpersistence.utils;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;

import java.util.Collections;
import java.util.List;

/**
 * Util class to handle opaque tokens. This is provided to handle backward compatibility
 * related use-cases.
 */
public class OpaqueTokenUtil {

    private static final Log log = LogFactory.getLog(OpaqueTokenUtil.class);

    /**
     * Find opaque refresh token from database.
     *
     * @param refreshToken Refresh token
     * @return AccessTokenDO  Access token data object.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving the refresh token.
     */
    public static AccessTokenDO findRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        return OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO().getRefreshToken(refreshToken);
    }

    /**
     * Validate opaque refresh token from revocation request and return the validation data object.
     *
     * @param token       Refresh Token
     * @param consumerKey Consumer Key
     * @return RefreshTokenValidationDataDO  Refresh token validation data object.
     * @throws IdentityOAuth2Exception if an error occurs while validating the refresh token.
     */
    public static RefreshTokenValidationDataDO validateOpaqueRefreshToken(String token, String consumerKey)
            throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO validationBean = validateRefreshToken(consumerKey, token);
        if (validationBean.getAccessToken() == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid Refresh Token provided for Client with Client Id : %s", consumerKey));
            }
            throw new IdentityOAuth2Exception("Persisted access token data not found.");
        }
        return validationBean;
    }

    /**
     * Validate opaque refresh token from database and return the validation data object.
     *
     * @param clientId     Client Id
     * @param refreshToken Refresh token
     * @return RefreshTokenValidationDataDO  Refresh token validation data object.
     * @throws IdentityOAuth2Exception if an error occurs while validating the refresh token.
     */
    private static RefreshTokenValidationDataDO validateRefreshToken(String clientId, String refreshToken)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug("Validating refresh token(hashed): " + DigestUtils.sha256Hex(refreshToken) + " client: "
                        + clientId);
            } else {
                log.debug("Validating refresh token for client: " + clientId);
            }
        }
        return OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                .validateRefreshToken(clientId, refreshToken);
    }

    /**
     * Validate Token Consent for Opaque tokens.
     *
     * @param validationBean RefreshTokenValidationDataDO
     */
    public static void validateTokenConsent(RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {

        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            String previousGrantType = validationBean.getGrantType();
            // Check if the previous grant type is consent refresh token type or not.
            if (!OAuthConstants.GrantTypes.REFRESH_TOKEN.equals(previousGrantType)) {
                // If the previous grant type is not a refresh token, then check if it's a consent token or not.
                if (OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(previousGrantType)) {
                    validationBean.setConsented(true);
                }
            } else {
                /* When previousGrantType == refresh_token, we need to check whether the original grant type
                 is consented or not. */
                AccessTokenDO accessTokenDOFromTokenIdentifier = OAuth2Util.getAccessTokenDOFromTokenIdentifier(
                        validationBean.getAccessToken(), false);
                validationBean.setConsented(accessTokenDOFromTokenIdentifier.isConsentedToken());
            }
        }
    }

    public static void revokeTokens(List<AccessTokenDO> accessTokens) throws IdentityOAuth2Exception {

        if (!accessTokens.isEmpty()) {
            // Revoking token from database.
            for (AccessTokenDO accessToken : accessTokens) {
                OAuthUtil.invokePreRevocationBySystemListeners(accessToken, Collections.emptyMap());
                OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .revokeAccessTokens(new String[]{accessToken.getAccessToken()}, OAuth2Util.isHashEnabled());
                OAuthUtil.invokePostRevocationBySystemListeners(accessToken, Collections.emptyMap());
            }
        }
    }
}
