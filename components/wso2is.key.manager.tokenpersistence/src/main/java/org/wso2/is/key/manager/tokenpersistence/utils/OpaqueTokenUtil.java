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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Util class to handle opaque tokens. This is provided to handle backward compatibility
 * related use-cases.
 */
public class OpaqueTokenUtil {

    private static final Log log = LogFactory.getLog(OpaqueTokenUtil.class);

    /**
     * Validate opaque refresh token and return the validation data object.
     *
     * @param tokenReqMessageContext Token request message context.
     * @return RefreshTokenValidationDataDO  Refresh token validation data object.
     * @throws IdentityOAuth2Exception if an error occurs while validating the refresh token.
     */
    public static RefreshTokenValidationDataDO validateOpaqueRefreshToken(
            OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = validateRefreshToken(tokenReq.getClientId(),
                tokenReq.getRefreshToken());
        if (validationBean.getAccessToken() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Refresh Token provided for Client with Client Id : " + tokenReq.getClientId());
            }
            throw new IdentityOAuth2Exception("Persisted access token data not found");
        }
        return validationBean;
    }

    /**
     * Validate opaque refresh token from revocation request and return the validation data object.
     *
     * @param token Refresh Token
     * @param consumerKey Consumer Key
     * @return RefreshTokenValidationDataDO  Refresh token validation data object.
     * @throws IdentityOAuth2Exception if an error occurs while validating the refresh token.
     */
    public static RefreshTokenValidationDataDO validateOpaqueRefreshToken(
            String token, String consumerKey) throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO validationBean = validateRefreshToken(consumerKey, token);
        if (validationBean.getAccessToken() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Refresh Token provided for Client with Client Id : " + consumerKey);
            }
            throw new IdentityOAuth2Exception("Persisted access token data not found");
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

        return OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO()
                .validateRefreshToken(clientId, refreshToken);
    }
}
