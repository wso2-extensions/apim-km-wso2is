
/*
 *   Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.is.notification;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.is.notification.event.TokenRevocationEvent;
import org.wso2.is.notification.internal.ServiceReferenceHolder;

import java.util.HashMap;
import java.util.Map;

/**
 * Token interceptor for Oauth Token revocation.
 */
public class ApimOauthEventInterceptor extends AbstractOAuthEventInterceptor {

    String notificationEndpoint;
    Map<String, String> headerMap = new HashMap<>();
    boolean enabled;

    public ApimOauthEventInterceptor() {

        super.init(initConfig);
        String endpointProperty = properties.getProperty(NotificationConstants.NOTIFICATION_ENDPOINT);
        if (StringUtils.isNotEmpty(endpointProperty)) {
            enabled = true;
            notificationEndpoint = NotificationUtil.replaceSystemProperty(endpointProperty);
            headerMap.putAll(NotificationUtil.extractHeadersMapFromProperties(properties));
        }
    }

    private static final Log log = LogFactory.getLog(ApimOauthEventInterceptor.class);

    @Override
    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO revokeRequestDTO,
                                              OAuthRevocationResponseDTO revokeResponseDTO, AccessTokenDO accessTokenDO,
                                              RefreshTokenValidationDataDO refreshTokenDO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        if (enabled && accessTokenDO != null) {
            try {
                long expiryTime = accessTokenDO.getIssuedTime().getTime() + accessTokenDO.getValidityPeriodInMillis();
                String accessToken = accessTokenDO.getAccessToken();
                String user = accessTokenDO.getAuthzUser().getUserName();
                int tenantID = accessTokenDO.getTenantID();
                String tenantDomain =
                        ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().getDomain(tenantID);
                OAuthAppDO oauthApp = OAuth2Util.getAppInformationByClientId(accessTokenDO.getConsumerKey());
                String tokenType = oauthApp.getTokenType();
                TokenRevocationEvent tokenRevocationEvent = new TokenRevocationEvent(accessToken, expiryTime, user,
                        accessTokenDO.getConsumerKey(), tokenType);
                tokenRevocationEvent.setTenantId(tenantID);
                tokenRevocationEvent.setTenantDomain(tenantDomain);
                publishEvent(tokenRevocationEvent);
            } catch (InvalidOAuthClientException e) {
                log.error("Error while retrieving token type", e);
            } catch (UserStoreException e) {
                log.error("Error while resolving tenantDomain", e);
            }
        }

    }

    @Override
    public void onPostTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO revokeRequestDTO,
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO revokeRespDTO,
            AccessTokenDO accessTokenDO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        if (enabled && accessTokenDO != null) {
            try {
                long expiryTime = accessTokenDO.getIssuedTime().getTime() + accessTokenDO.getValidityPeriodInMillis();
                String accessToken = accessTokenDO.getAccessToken();
                String user = accessTokenDO.getAuthzUser().getUserName();
                OAuthAppDO oauthApp = OAuth2Util.getAppInformationByClientId(accessTokenDO.getConsumerKey());
                String tokenType = oauthApp.getTokenType();
                TokenRevocationEvent tokenRevocationEvent = new TokenRevocationEvent(accessToken, expiryTime, user,
                        accessTokenDO.getConsumerKey(), tokenType);
                publishEvent(tokenRevocationEvent);
            } catch (InvalidOAuthClientException e) {
                log.error("Error while retrieving token type", e);
            }
        }
    }

    private void publishEvent(TokenRevocationEvent tokenRevocationEvent) {

        if (isEnabled()) {
            if (StringUtils.isNotEmpty(notificationEndpoint)) {
                EventSender.EventRunner eventRunner =
                        new EventSender.EventRunner(notificationEndpoint, headerMap, tokenRevocationEvent);
                EventSender.getInstance().execute(eventRunner);
            }
        }

    }
}
