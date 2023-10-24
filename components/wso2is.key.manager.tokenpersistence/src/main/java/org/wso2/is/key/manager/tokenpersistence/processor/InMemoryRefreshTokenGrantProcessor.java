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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
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
 * both Opaque and JWT.
 */
public class InMemoryRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {

    private static final Log log = LogFactory.getLog(InMemoryRefreshTokenGrantProcessor.class);
    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        if (!OAuth2Util.isJWT(tokenReq.getRefreshToken())) {
            log.debug("Refresh token is not a JWT. Hence, validating as an opaque token from database.");
            // For backward compatibility, we check whether it is available in idn_oauth2_token table.
            RefreshTokenValidationDataDO validationDO = OpaqueTokenUtil
                    .validateOpaqueRefreshToken(tokenReqMessageContext);
            //TODO: handle oauth cache
            OAuthUtil.clearOAuthCache(tokenReq.getClientId(), validationDO.getAuthorizedUser(),
                    OAuth2Util.buildScopeString(validationDO.getScope()), "NONE");
            return validationDO;
        }
        // validate JWT token signature, expiry time, not before time.
        log.debug("Refresh token is a JWT. Hence, validating signature, expiry time and indirect revocations.");
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(tokenReq.getRefreshToken());
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        // validate token type is refresh_token.
        if (!TokenMgtUtil.isRefreshTokenType(claimsSet)) {
            throw new IdentityOAuth2Exception("Invalid refresh token. token_type must be refresh_token.");
        }
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
        if (!TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
            throw new IdentityOAuth2Exception("Invalid token. Expiry time exceeded.");
        }
        TokenMgtUtil.checkNotBeforeTime(claimsSet.getNotBeforeTime());
        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY);
        // validate consumer key in the request against the token.
        if (!tokenReq.getClientId().equals(consumerKey)) {
            throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match");
        }
        /*
         * check whether the token is already revoked through direct revocations and following indirect
         * revocations.
         * 1. check if consumer app was changed.
         * 2. check if user was changed.
         */
        if (TokenMgtUtil.isTokenRevokedDirectly(tokenReq.getRefreshToken(), tokenReq.getClientId())
                || TokenMgtUtil.isTokenRevokedIndirectly(claimsSet.getSubject(), consumerKey,
                claimsSet.getIssueTime())) {
            throw new IllegalArgumentException("Invalid Access Token. ACTIVE access token is not found.");
        }
        // create new RefreshTokenValidationDO.
        Object scopes = claimsSet.getClaim(PersistenceConstants.SCOPE);
        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
        validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
        validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                - claimsSet.getIssueTime().getTime());
        validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
        AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
        validationDataDO.setAuthorizedUser(authenticatedUser);
        validationDataDO.setConsented(Boolean.parseBoolean(
                claimsSet.getClaim(PersistenceConstants.IS_CONSENTED).toString()));
        // if not active, an IdentityOAuth2Exception should have been thrown at the beginning.
        validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        //TODO: handle oauth cache
        OAuthUtil.clearOAuthCache(tokenReq.getClientId(), authenticatedUser,
                OAuth2Util.buildScopeString(validationDataDO.getScope()), "NONE");
        return validationDataDO;
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean,
                                String userStoreDomain, String clientId) throws IdentityOAuth2Exception {

        String refreshToken;
        long tokenExpirationTime;
        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(PREV_ACCESS_TOKEN);
        if (!OAuth2Util.isJWT(tokenReq.getRefreshToken())) { // for backward compatibility.
            refreshToken = tokenReq.getRefreshToken();
            tokenExpirationTime = oldAccessToken.getIssuedTime().getTime() + oldAccessToken.getValidityPeriodInMillis();
        } else {
            refreshToken = TokenMgtUtil.getTokenIdentifier(tokenReq.getRefreshToken(), clientId);
            SignedJWT signedJWT;
            try {
                signedJWT = SignedJWT.parse(tokenReq.getRefreshToken());
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                tokenExpirationTime = claimsSet.getExpirationTime().getTime();
            } catch (ParseException e) {
                throw new IdentityOAuth2Exception("Error while validating Token while persisting.", e);
            }
        }
        //Make the old refresh token inactive and persist it.
        ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(refreshToken, clientId,
                tokenExpirationTime);
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
