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

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
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
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;
import org.wso2.is.key.manager.tokenpersistence.utils.OpaqueTokenUtil;
import org.wso2.is.key.manager.tokenpersistence.utils.TokenMgtUtil;
import org.wso2.is.notification.event.InternalTokenRevocationUserEvent;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;

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

        if ((boolean) accessTokenDO.getProperty(PersistenceConstants.IS_PERSISTED)) {
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .revokeAccessTokens(new String[]{accessTokenDO.getAccessToken()});
        } else {
            // By this time, token identifier is already set in AccessTokenDO from the access token verification step.
            accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(
                    accessTokenDO.getAccessToken(), accessTokenDO.getConsumerKey(),
                    accessTokenDO.getIssuedTime().getTime() + accessTokenDO.getValidityPeriodInMillis());
        }
    }

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                   RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {

        String refreshTokenIdentifier = refreshTokenDO.getRefreshToken();
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug(String.format("Revoking refresh token(hashed): %s",
                        DigestUtils.sha256Hex(refreshTokenIdentifier)));
            } else {
                log.debug("Revoking refresh token.");
            }
        }
        if ((boolean) refreshTokenDO.getProperty(PersistenceConstants.IS_PERSISTED)) {
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .revokeAccessTokens(new String[]{refreshTokenDO.getAccessToken()});
        } else {
            refreshTokenDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(
                    refreshTokenIdentifier, revokeRequestDTO.getConsumerKey(), refreshTokenDO.getIssuedTime().getTime()
                            + refreshTokenDO.getValidityPeriodInMillis());
        }
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

        // Old tokens in the db will be revoked in the old way, since new tokens wouldn't have the mandatory claim.
        revokeMigratedTokenOfUser(username, userStoreManager);
        String userUUID = ((AbstractUserStoreManager) userStoreManager).getUserIDFromUserName(username);
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String organization = IdentityTenantUtil.getTenantDomain(tenantId);
        long revocationTime = Calendar.getInstance().getTimeInMillis();
        Map<String, Object> params = new HashMap<>();
        params.put(PersistenceConstants.ENTITY_ID, userUUID);
        params.put(PersistenceConstants.ENTITY_TYPE, PersistenceConstants.ENTITY_ID_TYPE_USER_ID);
        params.put(PersistenceConstants.REVOCATION_TIME, revocationTime);
        params.put(PersistenceConstants.ORGANIZATION, organization);
        params.put(PersistenceConstants.TENANT_ID, tenantId);
        params.put(PersistenceConstants.USERNAME, username);
        OAuthUtil.invokePreRevocationBySystemListeners(userUUID, params);
        try {
            ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().revokeTokensByUserEvent(userUUID,
                    PersistenceConstants.ENTITY_ID_TYPE_USER_ID, revocationTime, organization, 0);
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
                    .getOAuthConsumerAppsOfUser((String) params.get(PersistenceConstants.USERNAME),
                            (int) params.get(PersistenceConstants.TENANT_ID));
            for (OAuthAppDO oAuthAppDO : oAuthAppDOs) {
                String consumerKey = oAuthAppDO.getOauthConsumerKey();
                ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                        .revokeTokensByUserEvent(consumerKey, PersistenceConstants.ENTITY_ID_TYPE_CLIENT_ID,
                                (long) params.get(PersistenceConstants.REVOCATION_TIME),
                                params.get(PersistenceConstants.ORGANIZATION).toString(), 0);
                InternalTokenRevocationUserEvent internalTokenRevocationUserEvent =
                        new InternalTokenRevocationUserEvent(consumerKey, PersistenceConstants.ENTITY_ID_TYPE_CLIENT_ID,
                                params);
                org.wso2.is.notification.internal.ServiceReferenceHolder.getInstance()
                        .getEventSender().publishEvent(internalTokenRevocationUserEvent);
            }
        } catch (IdentityOAuthAdminException | IdentityOAuth2Exception e) {
            log.error("Error while persisting revoke rules for app tokens by user event.", e);
        }
    }

    /**
     * Revokes the migrated tokens of the user.
     *
     * @param username         username of the user
     * @param userStoreManager user store manager
     * @throws UserStoreException if an error occurs while revoking the tokens
     */
    private void revokeMigratedTokenOfUser(String username, UserStoreManager userStoreManager)
            throws UserStoreException {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(username);

        /* This userStoreDomain variable is used for access token table partitioning. So it is set to null when access
        token table partitioning is not enabled.*/
        userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(authenticatedUser);
            } catch (IdentityOAuth2Exception e) {
                log.error("Error occurred while getting user store domain for User ID : " + authenticatedUser, e);
                throw new UserStoreException(e);
            }
        }
        Set<String> clientIds;
        try {
            // get all the distinct client Ids authorized by this user
            clientIds = OAuthTokenPersistenceFactory.getInstance()
                    .getTokenManagementDAO().getAllTimeAuthorizedClientIds(authenticatedUser);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while retrieving apps authorized by User ID : " + authenticatedUser, e);
            throw new UserStoreException(e);
        }
        boolean isErrorOnRevokingTokens = false;
        for (String clientId : clientIds) {
            try {
                Set<AccessTokenDO> accessTokenDOs;
                try {
                    /*
                     * Token can be a migrated one from a previous product version. Hence, validating it against old
                     * token table.
                     */
                    AccessTokenDAO accessTokenDAO = ServiceReferenceHolder.getInstance().getMigratedAccessTokenDAO();
                    // retrieve all ACTIVE or EXPIRED access tokens for particular client authorized by this user
                    accessTokenDOs = accessTokenDAO.getAccessTokens(clientId, authenticatedUser, userStoreDomain, true);
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while retrieving access tokens issued for " +
                            "Client ID : " + clientId + ", User ID : " + authenticatedUser;
                    log.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
                if (log.isDebugEnabled() && CollectionUtils.isNotEmpty(accessTokenDOs)) {
                    log.debug("ACTIVE or EXPIRED access tokens found for the client: " + clientId + " for the user: "
                            + username);
                }
                // isTokenPreservingAtPasswordUpdateEnabled will be always set to false with this feature.
                List<AccessTokenDO> accessTokens = new ArrayList<>();
                for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                    // Only checking the token binding reference for cache clearing and not further, as it is not
                    // supported by the feature anyway.
                    String tokenBindingReference = NONE;
                    if (accessTokenDO.getTokenBinding() != null && StringUtils
                            .isNotBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
                        tokenBindingReference = accessTokenDO.getTokenBinding().getBindingReference();
                        // Cannot skip current token from being revoked.
                    }
                    // Clear cache.
                    OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
                    OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
                    OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                    OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser());
                    OAuthUtil.clearOAuthCache(accessTokenDO);
                    // Get unique scopes list
                    accessTokens.add(accessTokenDO);
                }
                // Always revoke all the tokens regardless of the token binding and token hashing enabled or not.
                try {
                    // Old tokens will be revoked in the old token table.
                    OpaqueTokenUtil.revokeTokens(accessTokens);
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while revoking Access Token";
                    log.error(errorMsg, e);
                    throw new UserStoreException(e);
                }
            } catch (UserStoreException e) {
                // Set a flag to throw an exception after revoking all the possible access tokens.
                // The error details are logged at the same place they are throwing.
                isErrorOnRevokingTokens = true;
            }
        }
        // Throw exception if there was any error found in revoking tokens.
        if (isErrorOnRevokingTokens) {
            throw new UserStoreException("Error occurred while revoking Access Tokens of the user " + username);
        }
    }
}
