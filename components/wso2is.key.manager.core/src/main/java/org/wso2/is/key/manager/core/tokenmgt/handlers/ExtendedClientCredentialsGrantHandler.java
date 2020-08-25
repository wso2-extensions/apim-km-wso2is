/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.is.key.manager.core.tokenmgt.handlers;


import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.ClientCredentialsGrantHandler;
import org.wso2.is.key.manager.core.internal.ServiceReferenceHolder;


/**
 * Extended grant handler for client credentials
 */
public class ExtendedClientCredentialsGrantHandler extends ClientCredentialsGrantHandler {
    private static final String VALIDITY_PERIOD = "validity_period";

    @Override
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx) {

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        long validityPeriod;

        if (parameters == null) {
            return true;
        }

        // find out validity period
        for (RequestParameter parameter : parameters) {
            if (VALIDITY_PERIOD.equals(parameter.getKey()) 
                    && parameter.getValue() != null && parameter.getValue().length > 0) {
                validityPeriod = Long.parseLong(parameter.getValue()[0]);
                //set validity time
                tokReqMsgCtx.setValidityPeriod(validityPeriod);
            }
        }

        return true;
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        boolean validateResult = super.validateGrant(tokReqMsgCtx);
        AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
        String username = user.getUserName();
        user.setUserName(username);
        tokReqMsgCtx.setAuthorizedUser(user);

        return validateResult;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) {
        return ServiceReferenceHolder.getInstance().getScopesIssuer().setScopes(tokReqMsgCtx);
    }
}
