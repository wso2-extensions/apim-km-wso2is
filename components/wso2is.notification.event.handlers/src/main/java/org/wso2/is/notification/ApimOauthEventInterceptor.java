
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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.AbstractOAuthEventInterceptor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.AuthorizationHandlerManager;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.is.notification.event.TokenRevocationEvent;
import org.wso2.is.notification.internal.ServiceReferenceHolder;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * Token interceptor for Oauth Token revocation.
 */
public class ApimOauthEventInterceptor extends AbstractOAuthEventInterceptor {

    String notificationEndpoint;
    Map<String, String> headerMap = new HashMap<>();
    boolean enabled;
    String username;
    char[] password;
    private EventSender eventSender;
    private static final String JWT = "JWT";

    public ApimOauthEventInterceptor() {

        super.init(initConfig);
        String endpointProperty = properties.getProperty(NotificationConstants.NOTIFICATION_ENDPOINT);
        String usernameProperty = properties.getProperty(NotificationConstants.USERNAME);
        String passwordProperty = properties.getProperty(NotificationConstants.PASSWORD);
        if (StringUtils.isNotEmpty(endpointProperty)) {
            enabled = true;
            notificationEndpoint = NotificationUtil.replaceSystemProperty(endpointProperty);
            headerMap.putAll(NotificationUtil.extractHeadersMapFromProperties(properties));
            if (StringUtils.isNotEmpty(usernameProperty) && StringUtils.isNotEmpty(passwordProperty)) {
                username = NotificationUtil.replaceSystemProperty(usernameProperty);
                password = NotificationUtil.replaceSystemProperty(passwordProperty).toCharArray();
                eventSender = new EventSender(notificationEndpoint, username, String.valueOf(password), headerMap);
            } else {
                eventSender = new EventSender(notificationEndpoint, headerMap);
            }
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
                TokenRevocationEvent tokenRevocationEvent = toTokenRevocationEvent(accessTokenDO);
                publishEvent(tokenRevocationEvent);
            } catch (InvalidOAuthClientException e) {
                log.error("Error while retrieving token type", e);
            } catch (UserStoreException e) {
                log.error("Error while resolving tenantDomain", e);
            }
        }

    }

    private TokenRevocationEvent toTokenRevocationEvent(AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception, InvalidOAuthClientException, UserStoreException {

        long expiryTime;
        long validityTime = accessTokenDO.getValidityPeriodInMillis();
        if (NotificationConstants.MAX_TOKEN_IDENTIFIER != validityTime) {
            expiryTime = accessTokenDO.getIssuedTime().getTime() + validityTime;
        } else {
            expiryTime = Long.MAX_VALUE;
        }
        String accessToken = accessTokenDO.getAccessToken();
        String user = accessTokenDO.getAuthzUser().getUserName();
        int tenantID = accessTokenDO.getTenantID();
        String tenantDomain =
                ServiceReferenceHolder.getInstance().getRealmService().getTenantManager().getDomain(tenantID);
        OAuthAppDO oauthApp = OAuth2Util.getAppInformationByClientId(accessTokenDO.getConsumerKey());
        String tokenType = oauthApp.getTokenType();
        accessToken = getJWTid(accessToken, oauthApp);
        TokenRevocationEvent tokenRevocationEvent = new TokenRevocationEvent(accessToken, expiryTime, user,
                accessTokenDO.getConsumerKey(), tokenType);
        tokenRevocationEvent.setTenantId(tenantID);
        tokenRevocationEvent.setTenantDomain(tenantDomain);
        return tokenRevocationEvent;
    }

    /**
     * If the usePersistedAccessTokenAlias is set to false in KM, full JWT token is saved in the DB.
     * The JTI should be extracted and used within the revocation event.
     *
     * @param accessToken
     * @param oauthApp
     * @return Extracted JTI if the full accessToken is given.
     * @throws IdentityOAuth2Exception
     */
    private String getJWTid(String accessToken, OAuthAppDO oauthApp) {
        if (JWT.equalsIgnoreCase(oauthApp.getTokenType())
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
                accessToken = getJWTid(accessToken, oauthApp);
                TokenRevocationEvent tokenRevocationEvent = new TokenRevocationEvent(accessToken, expiryTime, user,
                        accessTokenDO.getConsumerKey(), tokenType);
                publishEvent(tokenRevocationEvent);
            } catch (InvalidOAuthClientException e) {
                log.error("Error while retrieving token type", e);
            }
        }
    }

    @Override
    public void onPreTokenRevocationBySystem(AccessTokenDO accessTokenDO, Map<String, Object> params)
            throws IdentityOAuth2Exception {
    }

    @Override
    public void onPostTokenRevocationBySystem(AccessTokenDO accessTokenDO, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        if (enabled && accessTokenDO != null) {
            try {
                TokenRevocationEvent tokenRevocationEvent = toTokenRevocationEvent(accessTokenDO);
                publishEvent(tokenRevocationEvent);
            } catch (InvalidOAuthClientException e) {
                log.error("Error while retrieving token type", e);
            } catch (UserStoreException e) {
                log.error("Error while resolving tenantDomain", e);
            }
        }
    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params)
            throws IdentityOAuth2Exception {

        if (tokReqMsgCtx.getProperty(RefreshGrantHandler.PREV_ACCESS_TOKEN) != null &&
                tokReqMsgCtx.getProperty(AuthorizationHandlerManager.OAUTH_APP_PROPERTY) != null) {
            RefreshTokenValidationDataDO previousAccessToken =
                    (RefreshTokenValidationDataDO) tokReqMsgCtx.getProperty(RefreshGrantHandler.PREV_ACCESS_TOKEN);
            OAuthAppDO oAuthAppDO =
                    (OAuthAppDO) tokReqMsgCtx.getProperty(AuthorizationHandlerManager.OAUTH_APP_PROPERTY);
            String tokenToRevoke = getJWTid(previousAccessToken.getAccessToken(), oAuthAppDO);
            TokenRevocationEvent tokenRevocationEvent = new TokenRevocationEvent(tokenToRevoke,
                    previousAccessToken.getAccessTokenIssuedTime().getTime() + previousAccessToken
                            .getAccessTokenValidityInMillis(), previousAccessToken.getAuthorizedUser().getUserName(),
                    oAuthAppDO.getOauthConsumerKey(), oAuthAppDO.getTokenType());
            String tenantDomain = previousAccessToken.getAuthorizedUser().getTenantDomain();
            tokenRevocationEvent.setTenantDomain(tenantDomain);
            try {
                int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
                        .getTenantId(tenantDomain);
                tokenRevocationEvent.setTenantId(tenantId);
            } catch (UserStoreException e) {
                log.error("Error while finding tenant id", e);
            }
            publishEvent(tokenRevocationEvent);
        }
    }

    private void publishEvent(TokenRevocationEvent tokenRevocationEvent) {

        if (isEnabled()) {
            if (StringUtils.isNotEmpty(notificationEndpoint)) {
                eventSender.publishEvent(tokenRevocationEvent);
            }
        }
    }
}
