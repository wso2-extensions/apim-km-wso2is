/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
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
package org.wso2.is.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.AMDefaultKeyManagerImpl;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * This class provides the implementation to use "wso2is" for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class WSO2ISOAuthClient extends AMDefaultKeyManagerImpl {

    private static final Log log = LogFactory.getLog(WSO2ISOAuthClient.class);

    public String getType() {

        return WSO2ISConstants.WSO2IS_TYPE;
    }

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
        if (useKmAdminAsAppOwner()) {
            overrideKMAdminAsAppOwnerProperties(oauthAppRequest);
        }
        return super.createApplication(oauthAppRequest);
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest appInfoDTO) throws APIManagementException {
        if (useKmAdminAsAppOwner()) {
            overrideKMAdminAsAppOwnerProperties(appInfoDTO);
        }
        return super.updateApplication(appInfoDTO);
    }

    /**
     * Check whether KM admin has to be used as the OAuth application owner
     *
     * @return whether KM admin has to be used as the OAuth application owner
     */
    private boolean useKmAdminAsAppOwner() throws APIManagementException {
        boolean kmAdminAsAppOwner = false;
        Object kmAdminAsAppOwnerParameter = this.getKeyManagerConfiguration()
                .getParameter(WSO2ISConstants.KM_ADMIN_AS_APP_OWNER_NAME);
        if (kmAdminAsAppOwnerParameter != null) {
            kmAdminAsAppOwner = (boolean) kmAdminAsAppOwnerParameter;
        }
        return kmAdminAsAppOwner;
    }

    /**
     * Override the OAuth app username with the KM admin username and tenant domain
     * with the KM admin user's tenant domain
     */
    private void overrideKMAdminAsAppOwnerProperties(OAuthAppRequest oauthAppRequest) {
        String kmAdminUsername = this.getConfigurationParamValue(WSO2ISConstants.KEY_MANAGER_USERNAME);
        OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();
        oAuthApplicationInfo.addParameter(WSO2ISConstants.OAUTH_CLIENT_USERNAME, kmAdminUsername);
        String kmAdminTenantDomain = MultitenantUtils.getTenantDomain(kmAdminUsername);
        this.setTenantDomain(kmAdminTenantDomain);
    }
}
