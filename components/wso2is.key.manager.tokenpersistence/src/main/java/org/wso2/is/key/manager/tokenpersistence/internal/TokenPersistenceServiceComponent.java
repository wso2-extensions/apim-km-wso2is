/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com)
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
package org.wso2.is.key.manager.tokenpersistence.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.oauth.listener.OAuthApplicationMgtListener;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.is.key.manager.tokenpersistence.dao.ExtendedAccessTokenDAOImpl;
import org.wso2.is.key.manager.tokenpersistence.listner.APIMOAuthApplicationMgtListener;
import org.wso2.is.key.manager.tokenpersistence.processor.InMemoryOAuth2RevocationProcessor;
import org.wso2.is.key.manager.tokenpersistence.processor.InMemoryRefreshTokenGrantProcessor;
import org.wso2.is.key.manager.tokenpersistence.processor.InMemoryTokenProvider;
import org.wso2.is.notification.NotificationEventSenderService;

/**
 * KeyManager persistence component to handle non-token persistence.
 */
@Component(
        name = "key.manager.token.persistence.component",
        immediate = true
)
public class TokenPersistenceServiceComponent {

    private static final Log log = LogFactory.getLog(TokenPersistenceServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {

        log.info("Activating TokenPersistenceServiceComponent...");
        if (!OAuth2Util.isTokenPersistenceEnabled()) {
            log.info("Token persistence is not enabled. Registering related services..");
            cxt.getBundleContext().registerService(AccessTokenDAO.class, new ExtendedAccessTokenDAOImpl(), null);
            cxt.getBundleContext().registerService(OAuth2RevocationProcessor.class,
                    new InMemoryOAuth2RevocationProcessor(), null);
            cxt.getBundleContext().registerService(RefreshTokenGrantProcessor.class,
                    new InMemoryRefreshTokenGrantProcessor(), null);
            cxt.getBundleContext().registerService(TokenProvider.class, new InMemoryTokenProvider(), null);
            cxt.getBundleContext().registerService(OAuthApplicationMgtListener.class,
                    new APIMOAuthApplicationMgtListener(), null);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("KeyManagerCoreService bundle is deactivated");
        }
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
            name = "identityCoreInitializedEventService",
            service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(
            name = "wso2.is.notification.service",
            service = org.wso2.is.notification.NotificationEventSenderService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetNotificationEventSenderService")
    protected void setNotificationEventSenderService(NotificationEventSenderService eventSenderService) {

        if (eventSenderService != null && log.isDebugEnabled()) {
            log.debug("Notification Event Sender Service initialized");
        }
        ServiceReferenceHolder.getInstance().setEventSenderService(eventSenderService);
    }

    protected void unsetNotificationEventSenderService(NotificationEventSenderService eventSenderService) {

        ServiceReferenceHolder.getInstance().setEventSenderService(null);
    }
}
