/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.is.key.manager.tokenpersistence.validator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2JWTTokenValidator;

/**
 * In memory OAuth2 access token validator that supports "bearer" token type. This extends the default token validator
 * to retrieve app information using the consumer key only.
 */
public class InMemoryOAuth2TokenValidator extends OAuth2JWTTokenValidator {

    private static final Log log = LogFactory.getLog(InMemoryOAuth2TokenValidator.class);

    @Override
    public OAuthAppDO getAppInformation(AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving app information for the access token's consumer key "
                    + accessTokenDO.getConsumerKey());
        }
        OAuthAppDO app;
        try {
            /*
             * For non persistence we are not dependent on the token ID. Hence, we need to use the old way of getting
             * app information using the consumer key only assuming that the consumer key is unique across tenants.
             */
            app = OAuth2Util.getAppInformationByClientIdOnly(accessTokenDO.getConsumerKey());
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(String.format("Exception occurred when getting app information for "
                    + "client id %s ", accessTokenDO.getConsumerKey()), e);
        }
        return app;
    }
}
