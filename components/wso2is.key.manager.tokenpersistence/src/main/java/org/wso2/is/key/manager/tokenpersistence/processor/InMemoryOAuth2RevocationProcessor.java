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

package org.wso2.is.key.manager.tokenpersistence.processor;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;
import org.wso2.is.key.manager.tokenpersistence.utils.TokenMgtUtil;
import org.wso2.is.notification.event.InternalTokenRevocationUserEvent;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 * This class provides the implementation for revoking access tokens and refresh tokens in the context of InMemory
 * token persistence. It is designed to handle token revocation requests and perform the necessary actions to mark
 * tokens as revoked. The class implements the OAuth2RevocationProcessor interface to offer the following
 * functionality:
 * - Revoking access tokens, marking them as revoked in the persistence layer.
 * - Revoking refresh tokens, marking them as revoked in the persistence layer.
 * - Handling both JWT and opaque token formats for refresh token revocation.
 * This class also handles token hashing, token state updates, and interaction with the invalid token persistence
 * service.
 */
public class InMemoryOAuth2RevocationProcessor implements OAuth2RevocationProcessor {

    private static final Log log = LogFactory.getLog(InMemoryOAuth2RevocationProcessor.class);

    @Override
    public void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug(String.format("Revoking access token(hashed): %s",
                        DigestUtils.sha256Hex(accessTokenDO.getAccessToken())));
            } else {
                log.debug("Revoking access token.");
            }
        }
        // By this time, token identifier is already set in AccessTokenDO from the access token verification step.
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
        ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(
                accessTokenDO.getAccessToken(), accessTokenDO.getConsumerKey(), accessTokenDO.getIssuedTime().getTime()
                        + accessTokenDO.getValidityPeriodInMillis());
    }

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                   RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {

        String refreshTokenIdentifier;
        if (OAuth2Util.isJWT(revokeRequestDTO.getToken())) {
            SignedJWT signedJWT = TokenMgtUtil.parseJWT(revokeRequestDTO.getToken());
            JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
            refreshTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
        } else {
            // handling migrated opaque refresh tokens.
            refreshTokenIdentifier = revokeRequestDTO.getToken();
        }
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug(String.format("Revoking refresh token(hashed): %s",
                        DigestUtils.sha256Hex(refreshTokenIdentifier)));
            } else {
                log.debug("Revoking refresh token.");
            }
        }
        refreshTokenDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
        ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(
                refreshTokenIdentifier, revokeRequestDTO.getConsumerKey(), refreshTokenDO.getIssuedTime().getTime()
                        + refreshTokenDO.getValidityPeriodInMillis());
    }

    /**
     * Handles rule persistence and propagation for token revocation due to internal user events.
     *
     * @param username         user on which the event occurred
     * @param userStoreManager user store manager
     * @throws UserStoreException if an error occurs while handling user change events
     */
    @Override
    public boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {

        // Calling OAuthUtil.revokeTokens to handle migrations.
        // Old tokens in the db will be revoked in the old way, since new tokens wouldn't have the mandatory claim.
        OAuthUtil.revokeTokens(username, userStoreManager);
        String userUUID = ((AbstractUserStoreManager) userStoreManager).getUserIDFromUserName(username);
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String organization = IdentityTenantUtil.getTenantDomain(tenantId);
        long revocationTime = Calendar.getInstance().getTimeInMillis();
        Map<String, Object> params = new HashMap<>();
        params.put("subjectId", userUUID);
        params.put("subjectIdType", "USER_ID");
        params.put("revocationTime", revocationTime);
        params.put("organization", organization);
        params.put("tenantId", tenantId);
        params.put("tenantDomain", organization);
        params.put("username", username);
        OAuthUtil.invokePreRevocationBySystemListeners(userUUID, params);
        try {
            ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                    .revokeTokensByUserEvent(userUUID, "USER_ID", revocationTime, organization);
            revokeAppTokensOfUser(params);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while persisting revoke rules for tokens by user event.", e);
            return false;
        }
        OAuthUtil.invokePostRevocationBySystemListeners(userUUID, params);
        return true;
    }

    /**
     * Revokes the app tokens of the user.
     *
     * @param params parameters required to revoke the app tokens.
     */
    private void revokeAppTokensOfUser(Map<String, Object> params) {

        // Get client ids for the apps owned by user since the 'sub' claim for these are the consumer key.
        // The app tokens for those consumer keys should also be revoked.
        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        try {
            OAuthAppDO[] oAuthAppDOs = oAuthAppDAO
                    .getOAuthConsumerAppsOfUser((String) params.get("username"), (int) params.get("tenantId"));
            for (OAuthAppDO oAuthAppDO : oAuthAppDOs) {
                String consumerKey = oAuthAppDO.getOauthConsumerKey();
                String subjectIdType = "CLIENT_ID";
                ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                        .revokeTokensByUserEvent(consumerKey, subjectIdType,
                                (long) params.get("revocationTime"), params.get("organization").toString());
                InternalTokenRevocationUserEvent internalTokenRevocationUserEvent =
                        new InternalTokenRevocationUserEvent(consumerKey, subjectIdType, params);
                org.wso2.is.notification.internal.ServiceReferenceHolder.getInstance()
                        .getEventSender().publishEvent(internalTokenRevocationUserEvent);
            }
        } catch (IdentityOAuthAdminException | IdentityOAuth2Exception e) {
            log.error("Error while persisting revoke rules for app tokens by user event.", e);
        }
    }
}
