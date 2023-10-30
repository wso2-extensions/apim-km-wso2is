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
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;
import org.wso2.is.key.manager.tokenpersistence.utils.OpaqueTokenUtil;
import org.wso2.is.key.manager.tokenpersistence.utils.TokenMgtUtil;

import java.sql.Timestamp;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

/**
 * Refresh token grant processor to handle jwt refresh tokens during in memory token persistence scenarios. Works with
 * both migrated Opaque refresh tokens and JWTs.
 */
public class InMemoryRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {

    private static final Log log = LogFactory.getLog(InMemoryRefreshTokenGrantProcessor.class);
    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        return OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                .getVerifiedRefreshToken(tokenReq.getRefreshToken(), tokenReq.getClientId());
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean,
                                String userStoreDomain, String clientId) throws IdentityOAuth2Exception {

        try {
            String refreshTokenIdentifier;
            long tokenExpirationTime;
            OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
            RefreshTokenValidationDataDO oldAccessToken =
                    (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(PREV_ACCESS_TOKEN);
            if (!OAuth2Util.isJWT(tokenReq.getRefreshToken())) { // for backward compatibility.
                refreshTokenIdentifier = tokenReq.getRefreshToken();
                tokenExpirationTime = oldAccessToken.getIssuedTime().getTime()
                        + oldAccessToken.getValidityPeriodInMillis();
            } else {
                SignedJWT signedJWT = SignedJWT.parse(tokenReq.getRefreshToken());
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                refreshTokenIdentifier = TokenMgtUtil.getTokenIdentifier(claimsSet);
                tokenExpirationTime = claimsSet.getExpirationTime().getTime();
            }
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                    log.debug(String.format("Invalidating previous refresh token (hashed): %s",
                            DigestUtils.sha256Hex(refreshTokenIdentifier)));
                } else {
                    log.debug("Invalidating previous refresh token.");
                }
            }
            // Make the old refresh token inactive and persist it.
            ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService()
                    .addInvalidToken(refreshTokenIdentifier, clientId, tokenExpirationTime);
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while parsing refresh token while persisting.", e);
        }
    }

    @Override
    public AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
                                               OAuth2AccessTokenReqDTO tokenReq,
                                               RefreshTokenValidationDataDO validationBean, String tokenType) {

        Timestamp timestamp = new Timestamp(new Date().getTime());
        String tokenId = UUID.randomUUID().toString();
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(tokenReq.getClientId());
        accessTokenDO.setAuthzUser(tokReqMsgCtx.getAuthorizedUser());
        accessTokenDO.setScope(tokReqMsgCtx.getScope());
        accessTokenDO.setTokenType(tokenType);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setGrantType(tokenReq.getGrantType());
        accessTokenDO.setIssuedTime(timestamp);
        accessTokenDO.setTokenBinding(tokReqMsgCtx.getTokenBinding());
        // If refresh token in request was consented, set the consented true on new access token and refresh token.
        if (validationBean.isConsented()) {
            accessTokenDO.setIsConsentedToken(true);
            tokReqMsgCtx.setConsentedToken(true);
        }
        return accessTokenDO;
    }

    @Override
    public boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean,
                                        String userStoreDomain) {

        return true;
    }
}
