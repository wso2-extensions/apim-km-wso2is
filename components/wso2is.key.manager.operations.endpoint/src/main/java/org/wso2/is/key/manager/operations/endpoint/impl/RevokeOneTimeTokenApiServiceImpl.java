/*
 *  Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.is.key.manager.operations.endpoint.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.is.key.manager.operations.endpoint.RevokeOneTimeTokenApiService;
import org.wso2.is.key.manager.operations.endpoint.dto.RevokeTokenInfoDTO;
import org.wso2.is.key.manager.operations.endpoint.userinfo.util.UserInfoUtil;

import java.util.Collections;
import javax.ws.rs.core.Response;

/**
 * Service Implementation for One Time Token Revocation
 */
public class RevokeOneTimeTokenApiServiceImpl implements RevokeOneTimeTokenApiService {

    /**
     * This method calls the Identity server to revoke the One Time Token
     *
     * @param revokeTokenInfo {@link RevokeTokenInfoDTO}  with JWT token and consumer key
     * @return response whether the request is completed or any other issue
     */
    public Response revokeOneTimeTokenPost(RevokeTokenInfoDTO revokeTokenInfo, MessageContext messageContext) {

        String token = revokeTokenInfo.getToken();
        String consumerKey = revokeTokenInfo.getConsumerKey();

        if (StringUtils.isEmpty(token)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(UserInfoUtil.getError(Response.Status.BAD_REQUEST.toString(),
                            "Could not revoke the token because the token id is empty", null
                    ))
                    .build();
        }
        if (StringUtils.isEmpty(consumerKey)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(UserInfoUtil.getError(Response.Status.BAD_REQUEST.toString(),
                            "Could not revoke the token because the consumer key is empty", null))
                    .build();
        }
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setAuthenticated(true);
        oAuthClientAuthnContext.setClientId(consumerKey);
        OAuthRevocationRequestDTO revocationRequest =
                OAuth2Util.buildOAuthRevocationRequest(oAuthClientAuthnContext, token);
        OAuthRevocationResponseDTO oauthRevokeResponse = getOauth2Service().revokeTokenByOAuthClient(revocationRequest);
        if (oauthRevokeResponse.getErrorMsg() == null) {
            return Response.status(Response.Status.OK)
                    .entity(UserInfoUtil.getError(Response.Status.OK.toString(),
                            "Successfully revoked token " + getMaskedToken(token), null))
                    .build();
        } else {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(UserInfoUtil.getError(Response.Status.INTERNAL_SERVER_ERROR.toString(),
                            oauthRevokeResponse.getErrorMsg(),
                            "Revocation of the token" + getMaskedToken(token) + "is failed"))
                    .build();
        }
    }

    private OAuth2Service getOauth2Service() {

        return (OAuth2Service) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2Service.class, null);
    }

    private String getMaskedToken(String token) {

        StringBuilder maskedTokenBuilder = new StringBuilder();
        if (token != null) {
            int allowedVisibleLen = Math.min(token.length() / 5, 8);
            if (token.length() > 36) {
                maskedTokenBuilder.append("...");
                maskedTokenBuilder.append(String.join("", Collections.nCopies(36, "X")));
            } else {
                maskedTokenBuilder.append(String.join("", Collections.nCopies(token.length()
                        - allowedVisibleLen, "X")));
            }
            maskedTokenBuilder.append(token.substring(token.length() - allowedVisibleLen));
        }
        return maskedTokenBuilder.toString();
    }
}
