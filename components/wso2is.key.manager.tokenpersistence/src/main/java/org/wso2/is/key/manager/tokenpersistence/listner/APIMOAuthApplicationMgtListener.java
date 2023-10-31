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
package org.wso2.is.key.manager.tokenpersistence.listner;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;

import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.listener.OAuthApplicationMgtListener;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.is.notification.event.InternalTokenRevocationConsumerKeyEvent;
import org.wso2.is.notification.internal.ServiceReferenceHolder;

import java.util.Calendar;
import java.util.Properties;

/**
 * This class listens to OAuth application management events.
 * It is used to revoke tokens when a consumer key is updated.
 */
public class APIMOAuthApplicationMgtListener implements OAuthApplicationMgtListener {

    private static final Log log = LogFactory.getLog(APIMOAuthApplicationMgtListener.class);


    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public int getExecutionOrder() {
        return 0;
    }

    @Override
    public void doPreUpdateConsumerApplication(OAuthConsumerAppDTO oAuthConsumerAppDTO)
            throws IdentityOAuthAdminException {

    }

    @Override
    public void doPreUpdateConsumerApplicationState(String s, String s1) throws IdentityOAuthAdminException {

    }

    @Override
    public void doPreRemoveOAuthApplicationData(String s) throws IdentityOAuthAdminException {

    }

    @Override
    public void doPostRegenerateClientSecret(String consumerKey, Properties properties)
            throws IdentityOAuthAdminException {
        long revocationTime = Calendar.getInstance().getTimeInMillis();
        String organization = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        properties.put("revocationTime", revocationTime);
        properties.put("organization", organization);

        try {
            org.wso2.is.key.manager.tokenpersistence.internal.ServiceReferenceHolder.getInstance()
                    .getInvalidTokenPersistenceService()
                    .revokeTokensByConsumerKeyEvent(consumerKey, revocationTime, organization);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while persisting revoking access tokens by consumer key event.", e);
            throw new IdentityOAuthAdminException(e.getMessage(), e);
        }
        InternalTokenRevocationConsumerKeyEvent internalTokenRevocationConsumerKeyEvent
                = new InternalTokenRevocationConsumerKeyEvent(consumerKey, properties);
        ServiceReferenceHolder.getInstance().getEventSender().publishEvent(internalTokenRevocationConsumerKeyEvent);
    }

}
