/*
 *   Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
 *
 *   WSO2 LLC. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.notification;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.listener.OAuthApplicationMgtListener;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.is.notification.event.TokenRevocationBatchEvent;
import org.wso2.is.notification.event.TokenRevocationEvent;
import org.wso2.is.notification.internal.ServiceReferenceHolder;

import java.text.ParseException;
import java.util.Set;

/**
 * Listener interface for OAuth application management CRUD operations.
 */
public class APIMOAuthApplicationMgtListener implements OAuthApplicationMgtListener {

    private static final Log log = LogFactory.getLog(APIMOAuthApplicationMgtListener.class);

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public int getExecutionOrder() {
        return 0;
    }

    @Override
    public void doPreUpdateConsumerApplication(OAuthConsumerAppDTO oAuthConsumerAppDTO)
            throws IdentityOAuthAdminException {
    }

    @Override
    public void doPreUpdateConsumerApplicationState(String consumerKey, String newState)
            throws IdentityOAuthAdminException {
        if (newState.equals(OAuthConstants.OauthAppStates.APP_STATE_REVOKED)) {
            revokeAccessTokensAssociatedWithOAuthApplication(consumerKey);
        }
    }

    @Override
    public void doPreRemoveOAuthApplicationData(String consumerKey) throws IdentityOAuthAdminException {

    }

    /**
     * Handle revocation of access tokens when an OAuth application is revoked.
     *
     * @param consumerKey The consumer key of the OAuth application.
     */
    private void revokeAccessTokensAssociatedWithOAuthApplication(String consumerKey) {
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        int tenantId;
        try {
            tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            log.error("Error while finding tenant id for domain: " + tenantDomain, e);
            return;
        }

        try {
            // Get all active access tokens for the consumer key
            Set<AccessTokenDO> accessTokenDOs = OAuthTokenPersistenceFactory.getInstance()
                    .getAccessTokenDAO().getActiveAcessTokenDataByConsumerKey(consumerKey);

            if (accessTokenDOs == null || accessTokenDOs.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("No active access tokens found for consumer key: " + consumerKey);
                }
                return;
            }

            // Get OAuth app info for token type
            OAuthAppDO oauthApp = OAuth2Util.getAppInformationByClientId(consumerKey);
            String tokenType = oauthApp.getTokenType();

            // Create TokenRevocationEvents object
            TokenRevocationBatchEvent tokenRevocationEvents = new TokenRevocationBatchEvent(consumerKey);

            long currentTime = System.currentTimeMillis();

            // Create TokenRevocationEvent for each access token
            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                try {
                    long expiryTime;
                    long validityTime = accessTokenDO.getValidityPeriod();
                    if (validityTime > 0) {
                        expiryTime = accessTokenDO.getIssuedTime().getTime() + validityTime;
                    } else {
                        expiryTime = Long.MAX_VALUE;
                    }
                    if (expiryTime > currentTime) {
                        TokenRevocationEvent tokenRevocationEvent = createTokenRevocationEvent(
                                accessTokenDO, expiryTime, tokenType, tenantId, tenantDomain);
                        tokenRevocationEvents.addTokenRevocationEventToList(tokenRevocationEvent);
                    }
                } catch (Exception e) {
                    log.error("Error creating TokenRevocationEvent for token: " +
                            accessTokenDO.getAccessToken(), e);
                }
            }
            tokenRevocationEvents.setTenantId(tenantId);
            tokenRevocationEvents.setTenantDomain(tenantDomain);

            // Publish the list of token revocation events
            if (!tokenRevocationEvents.getTokenRevocationEventList().isEmpty()) {
                ServiceReferenceHolder.getInstance().getEventSenderService().publishEvent(tokenRevocationEvents);
                if (log.isDebugEnabled()) {
                    log.debug("Published " + tokenRevocationEvents.getTokenRevocationEventList().size() +
                            " token revocation events for consumer key: " + consumerKey);
                }
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while retrieving access tokens for consumer key: " + consumerKey, e);
        } catch (InvalidOAuthClientException e) {
            log.error("Error while retrieving OAuth app information for consumer key: " + consumerKey, e);
        }
    }

    /**
     * Create a TokenRevocationEvent from an AccessTokenDO.
     *
     * @param accessTokenDO The access token data object
     * @param expiryTime The expiry time of the accessToken
     * @param tokenType The token type
     * @param tenantId The tenant ID
     * @param tenantDomain The tenant domain
     * @return TokenRevocationEvent
     */
    private TokenRevocationEvent createTokenRevocationEvent(AccessTokenDO accessTokenDO, long expiryTime,
                                                            String tokenType, int tenantId, String tenantDomain) {
        String accessToken = accessTokenDO.getAccessToken();
        String user = accessTokenDO.getAuthzUser().getUserName();
        String consumerKey = accessTokenDO.getConsumerKey();

        // Extract JTI if the token is a JWT
        accessToken = getJWTid(accessToken, tokenType);

        TokenRevocationEvent tokenRevocationEvent = new TokenRevocationEvent(
                accessToken, expiryTime, user, consumerKey, tokenType);
        tokenRevocationEvent.setTenantId(tenantId);
        tokenRevocationEvent.setTenantDomain(tenantDomain);

        return tokenRevocationEvent;
    }

    /**
     * If the usePersistedAccessTokenAlias is set to false in KM, full JWT token is saved in the DB.
     * The JTI should be extracted and used within the revocation event.
     *
     * @param accessToken The access token
     * @param tokenType The token type
     * @return Extracted JTI if the full accessToken is given.
     */
    private String getJWTid(String accessToken, String tokenType) {
        if ("JWT".equalsIgnoreCase(tokenType)
                && StringUtils.countMatches(accessToken, NotificationConstants.DOT) == 2) {
            try {
                SignedJWT signedJWT = SignedJWT.parse(accessToken);
                JWTClaimsSet payload = signedJWT.getJWTClaimsSet();
                if (payload.getJWTID() != null) {
                    accessToken = payload.getJWTID();
                } else {
                    accessToken = signedJWT.getSignature().toString();
                }
            } catch (ParseException e) {
                log.error("Error while extracting the JTI from JWT token, for token revocation", e);
            }
        }
        return accessToken;
    }
}
