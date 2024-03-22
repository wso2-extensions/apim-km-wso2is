/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.is7.client.internal;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.apimgt.impl.APIManagerConfigurationService;
import org.wso2.carbon.apimgt.impl.keymgt.KeyManagerEventHandler;
import org.wso2.carbon.apimgt.notification.NotificationEventService;
import org.wso2.is7.client.WSO2ISNotificationEventHandler;

/**
 * Activation class for WSO2ISNotificationEventHandler
 */
@Component(immediate = true, name = "org.wso2.is.client.component")
public class WSO2ISClientComponent {

    @Activate
    protected void activate(ComponentContext ctxt) {
        ctxt.getBundleContext().registerService(KeyManagerEventHandler.class, new WSO2ISNotificationEventHandler(),
                null);
    }

    @Reference(name = "apim.notification.component",
            service = org.wso2.carbon.apimgt.notification.NotificationEventService.class,
            cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetNotificationEventService")
    protected void setNotificationEventService(NotificationEventService neService) {
        ServiceReferenceHolder.getInstance().setNotificationEventService(neService);
    }

    protected void unsetNotificationEventService(NotificationEventService neService) {
        ServiceReferenceHolder.getInstance().setNotificationEventService(null);
    }

    @Reference(name = "api.manager.config.service",
            service = org.wso2.carbon.apimgt.impl.APIManagerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAPIManagerConfigurationService")
    protected void setAPIManagerConfigurationService(APIManagerConfigurationService amcService) {

        ServiceReferenceHolder.getInstance().setAPIManagerConfigurationService(amcService);
    }

    protected void unsetAPIManagerConfigurationService(APIManagerConfigurationService amcService) {

        ServiceReferenceHolder.getInstance().setAPIManagerConfigurationService(null);
    }

}
