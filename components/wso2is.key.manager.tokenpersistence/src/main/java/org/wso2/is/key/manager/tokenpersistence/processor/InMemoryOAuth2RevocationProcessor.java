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
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.is.key.manager.tokenpersistence.PersistenceConstants;
import org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder;
import org.wso2.is.key.manager.tokenpersistence.utils.TokenMgtUtil;

import java.sql.Timestamp;
import java.util.UUID;

/**
 * Token revocation related implementation for InMemory persistence.
 */
public class InMemoryOAuth2RevocationProcessor implements OAuth2RevocationProcessor {

    @Override
    public void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception {

        //TODO:// Handle OAuth Cache
        //TODO:// Decide whether token binding is needed
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
        ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(
                accessTokenDO.getAccessToken(), accessTokenDO.getConsumerKey(), accessTokenDO.getIssuedTime().getTime()
                        + accessTokenDO.getValidityPeriodInMillis());
    }

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                   RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {

        //TODO:// Handle OAuth Cache
        //TODO:// Decide whether token binding is needed
        //TODO:// handle code for backward compatibleness for migrating opaque refresh tokens
        refreshTokenDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
        ServiceReferenceHolder.getInstance().getInvalidTokenPersistenceService().addInvalidToken(
                TokenMgtUtil.getTokenIdentifier(revokeRequestDTO.getToken(), revokeRequestDTO.getConsumerKey()),
                revokeRequestDTO.getConsumerKey(), refreshTokenDO.getIssuedTime().getTime()
                        + refreshTokenDO.getValidityPeriodInMillis());
    }

    @Override
    public RefreshTokenValidationDataDO getRevocableRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {

        RefreshTokenValidationDataDO validationDataDO = null;
        TokenMgtUtil.isJWTToken(revokeRequestDTO.getToken());
        //TODO:// handle code for backward compatibleness for migrating opaque refresh tokens
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(revokeRequestDTO.getToken());
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY);
        // validate consumer key in the request against the token.
        if (!revokeRequestDTO.getConsumerKey().equals(consumerKey)) {
            throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match.");
        }
        /*
         * check whether the token is not already revoked through direct revocations and following indirect
         * revocations.
         * 1. check if consumer app was changed.
         * 2. check if user was changed.
         */
        if (!TokenMgtUtil.isTokenRevokedDirectly(revokeRequestDTO.getToken(), consumerKey)
                && !TokenMgtUtil.isTokenRevokedIndirectly(claimsSet.getSubject(), consumerKey,
                claimsSet.getIssueTime())) {
            validationDataDO = new RefreshTokenValidationDataDO();
            // set expiration state according to jwt claim in it.
            if (TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            } else {
                validationDataDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
            }
            // set other fields from jwt claims.
            validationDataDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            validationDataDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            validationDataDO.setScope(TokenMgtUtil.getScopes(claimsSet.getClaim(PersistenceConstants.SCOPE)));
            AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
            validationDataDO.setAuthorizedUser(authenticatedUser);
            //TODO:// handle oauth caching
        }
        return validationDataDO;
    }

    @Override
    public AccessTokenDO getRevocableAccessToken(OAuthRevocationRequestDTO revokeRequestDTO)
            throws IdentityOAuth2Exception {

        AccessTokenDO accessTokenDO = null;
        TokenMgtUtil.isJWTToken(revokeRequestDTO.getToken());
        SignedJWT signedJWT = TokenMgtUtil.parseJWT(revokeRequestDTO.getToken());
        JWTClaimsSet claimsSet = TokenMgtUtil.getTokenJWTClaims(signedJWT);
        TokenMgtUtil.validateJWTSignature(signedJWT, claimsSet);
        String consumerKey = (String) claimsSet.getClaim(PersistenceConstants.AUTHORIZATION_PARTY);
        // validate consumer key in the request against the token.
        if (!revokeRequestDTO.getConsumerKey().equals(consumerKey)) {
            throw new IdentityOAuth2Exception("Invalid refresh token. Consumer key does not match.");
        }
        /*
         * check whether the token is not already revoked through direct revocations and following indirect
         * revocations, if so return nothing.
         * 1. check if consumer app was changed.
         * 2. check if user was changed.
         */
        if (!TokenMgtUtil.isTokenRevokedDirectly(revokeRequestDTO.getToken(), consumerKey)
                && !TokenMgtUtil.isTokenRevokedIndirectly(
                claimsSet.getSubject(), consumerKey, claimsSet.getIssueTime())) {
            accessTokenDO = new AccessTokenDO();
            String tokenId = UUID.randomUUID().toString();
            accessTokenDO.setTokenId(tokenId); //TODO: check if we really need this
            accessTokenDO.setAccessToken(TokenMgtUtil.getTokenIdentifier(revokeRequestDTO.getToken(), consumerKey));
            accessTokenDO.setConsumerKey(consumerKey);
            // check if token is expired and set tokenState EXPIRED or ACTIVE.
            if (TokenMgtUtil.isActive(claimsSet.getExpirationTime())) {
                accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            } else {
                accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
            }
            // TODO:// need to decide how to determine the consented state for the previous access token or if previous
            accessTokenDO.setIsConsentedToken(false);
            // set other fields from jwt claims.
            accessTokenDO.setIssuedTime(new Timestamp(claimsSet.getIssueTime().getTime()));
            accessTokenDO.setValidityPeriodInMillis(claimsSet.getExpirationTime().getTime()
                    - claimsSet.getIssueTime().getTime());
            accessTokenDO.setScope(TokenMgtUtil.getScopes(claimsSet.getClaim(PersistenceConstants.SCOPE)));
            AuthenticatedUser authenticatedUser = TokenMgtUtil.getAuthenticatedUser(claimsSet);
            accessTokenDO.setAuthzUser(authenticatedUser);
            //TODO:// handle oauth caching
        }
        return accessTokenDO;
    }

    @Override
    public boolean isRefreshTokenType(OAuthRevocationRequestDTO revokeRequestDTO) {

        return StringUtils.equals(GrantType.REFRESH_TOKEN.toString(), revokeRequestDTO.getTokenType());
    }
}
