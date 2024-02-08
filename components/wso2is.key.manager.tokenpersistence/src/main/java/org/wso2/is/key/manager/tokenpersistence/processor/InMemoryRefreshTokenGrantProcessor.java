/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
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
 * Refresh token grant handler to handle jwt refresh tokens
 *
 */

public class InMemoryRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {
    
    private static final Log log = LogFactory.getLog(InMemoryRefreshTokenGrantProcessor.class);
    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {
        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        
        
        if (!OAuth2Util.isJWT(tokenReq.getRefreshToken())) {
            if (ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().isInvalidToken(
                    tokenReq.getRefreshToken(), PersistenceConstants.TOKEN_TYPE_REFRESH_TOKEN,
                    tokenReq.getClientId())) {
                throw new IdentityOAuth2Exception("Invalid refresh token. token is already used.");
            }
            //For backward compatibility, we check whether it is avaliable in idn_oauth2_token table
            RefreshTokenValidationDataDO validationDO = OpaqueTokenUtil
                    .validateOpaqueRefreshToken(tokenReqMessageContext);
            OAuthUtil.clearOAuthCache(tokenReq.getClientId(), validationDO.getAuthorizedUser(),
                    OAuth2Util.buildScopeString(validationDO.getScope()), "NONE");            
            return validationDO;
            
        }
        //validate JWT token signature, expiry time, not before time
        try {
            // check whether the token is already revoked
            if (ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().isInvalidToken(
                    TokenMgtUtil.getTokenIdentifier(tokenReq.getRefreshToken(), tokenReq.getClientId()),
                    PersistenceConstants.TOKEN_TYPE_REFRESH_TOKEN, tokenReq.getClientId())) {
                throw new IdentityOAuth2Exception("Invalid refresh token. token is already used.");
            }
            
            SignedJWT signedJWT = SignedJWT.parse(tokenReq.getRefreshToken());
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            if (claimsSet == null) {
                throw new IdentityOAuth2Exception("Claim values are empty in the given Token.");
            }
            IdentityProvider identityProvider = TokenMgtUtil.getResidentIDPForIssuer(claimsSet.getIssuer());
            if (!TokenMgtUtil.validateSignature(signedJWT, identityProvider)) {
                throw new IdentityOAuth2Exception(("Invalid signature"));
            }
            if (!TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
                throw new IdentityOAuth2Exception("Invalid token. Expiry time exceeded");
                //TODO://handle error properly with invalid grant error
            }
            checkNotBeforeTime(claimsSet.getNotBeforeTime());
            Object consumerKey = claimsSet.getClaim("azp");
            if (!tokenReq.getClientId().equals(consumerKey)) {
                throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match");
            }
            //validate token against persisted invalid refresh tokens
            Object scopes = claimsSet.getClaim("scope");
            
            //create new RefreshTokenValidationDO
            RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            validationDataDO.setGrantType("refresh_token");
            validationDataDO.setScope(TokenMgtUtil.getScopes(scopes));
            AuthenticatedUser user = OAuth2Util.getUserFromUserName((String) claimsSet.getClaim("given_name"));
            user.setAuthenticatedSubjectIdentifier(claimsSet.getSubject());
            validationDataDO.setAuthorizedUser(user);
            validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            
            OAuthUtil.clearOAuthCache(tokenReq.getClientId(), user,
                    OAuth2Util.buildScopeString(validationDataDO.getScope()), "NONE");
            return validationDataDO;
        } catch (JOSEException | ParseException e) {
            throw new IdentityOAuth2Exception("Error while validating Token.", e);
        }
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean,
            String userStoreDomain, String clientId) throws IdentityOAuth2Exception {
        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(PREV_ACCESS_TOKEN);
        
        String refreshToken;
        Long tokenExpirationTime; 
        if (!OAuth2Util.isJWT(tokenReq.getRefreshToken())) { // for backward compatibility.
            refreshToken = tokenReq.getRefreshToken();
            tokenExpirationTime = oldAccessToken.getIssuedTime().getTime() + oldAccessToken.getValidityPeriodInMillis();
        } else {
            //TODO: check whether extract it from the jwt is correct
            refreshToken = TokenMgtUtil.getTokenIdentifier(tokenReq.getRefreshToken(), clientId);
            SignedJWT signedJWT;
            try {
                //TODO: can optimize the parsing by adding the parsed token in validateRefreshToken() 
                //to tokenReqMessageContext
                signedJWT = SignedJWT.parse(tokenReq.getRefreshToken());
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                tokenExpirationTime = claimsSet.getExpirationTime().getTime();
            } catch (ParseException e) {
                throw new IdentityOAuth2Exception("Error while validating Token while persisting.", e);
            }           
        }
        //If JWT make the old refresh token inactive and persist it
        ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(refreshToken,
                PersistenceConstants.TOKEN_TYPE_REFRESH_TOKEN, clientId, tokenExpirationTime);
    }

    @Override
    public AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
            OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean, String tokenType)
            throws IdentityOAuth2Exception {
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
        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            //not possible to determine the previous access token, hence setting default value false.
            accessTokenDO.setIsConsentedToken(false);
            tokReqMsgCtx.setConsentedToken(false);
        }
        return accessTokenDO;
    }

    @Override
    public boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean,
            String userStoreDomain) throws IdentityOAuth2Exception {
        return true;
    }
    
    private boolean checkNotBeforeTime(Date notBeforeTime) throws IdentityOAuth2Exception {

        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();
            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("Token is used before Not_Before_Time." +
                            ", Not Before Time(ms) : " + notBeforeTimeMillis +
                            ", TimeStamp Skew : " + timeStampSkewMillis +
                            ", Current Time : " + currentTimeInMillis + ". Token Rejected and validation terminated.");
                }
                throw new IdentityOAuth2Exception("Token is used before Not_Before_Time.");
            }
            if (log.isDebugEnabled()) {
                log.debug("Not Before Time(nbf) of Token was validated successfully.");
            }
        }
        return true;
    }
}
