/*
 *   Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
 *
 *   WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.is.notification.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.listener.OAuthApplicationMgtListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.is.notification.APIMOAuthApplicationMgtListener;
import org.wso2.is.notification.APIMTokenExchangeAuditLogger;
import org.wso2.is.notification.ApimOauthEventInterceptor;

/**
 * Activation class for notification
 */
@Component(immediate = true, name = "org.wso2.is.notification.component")
public class NotificationServiceComponent {

    private static final Log log = LogFactory.getLog(NotificationServiceComponent.class);
    ServiceRegistration<OAuthEventInterceptor> serviceRegistration;
    private ServiceRegistration<OAuthEventInterceptor> auditLoggerServiceRegistration;
    private ServiceRegistration<OAuthApplicationMgtListener> oAuthApplicationMgtListenerServiceRegistration;

    @Activate
    protected void activate(ComponentContext componentContext) throws Exception {

        BundleContext bundleContext = componentContext.getBundleContext();
        serviceRegistration =
                bundleContext.registerService(OAuthEventInterceptor.class, new ApimOauthEventInterceptor(), null);
        auditLoggerServiceRegistration =
                bundleContext.registerService(OAuthEventInterceptor.class, new APIMTokenExchangeAuditLogger(), null);
        oAuthApplicationMgtListenerServiceRegistration =
                bundleContext.registerService(OAuthApplicationMgtListener.class, new APIMOAuthApplicationMgtListener(),
                        null);
    }

    @Reference(
            name = "user.realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (realmService != null && log.isDebugEnabled()) {
            log.debug("Realm service initialized");
        }
        ServiceReferenceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        ServiceReferenceHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent",
            service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEvent")
    protected void setIdentityCoreInitializedEvent(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        // Nothing to implement.
    }

    protected void unsetIdentityCoreInitializedEvent(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        // Nothing to implement.
    }

    @Reference(
            name = "config.context.service",
            service = org.wso2.carbon.utils.ConfigurationContextService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationContextService")
    protected void setConfigurationContextService(ConfigurationContextService contextService) {

        ServiceReferenceHolder.getInstance().setContextService(contextService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService contextService) {

        ServiceReferenceHolder.getInstance().setContextService(null);
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
        if (auditLoggerServiceRegistration != null) {
            auditLoggerServiceRegistration.unregister();
        }
        if (oAuthApplicationMgtListenerServiceRegistration != null) {
            oAuthApplicationMgtListenerServiceRegistration.unregister();
        }
        if (log.isDebugEnabled()) {
            log.info("Oauth Listeners disabled");
        }
    }
}
