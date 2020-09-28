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
 * /
 */

package org.wso2.is.key.manager.core.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.is.key.manager.core.handlers.ExtendedISAuthHandler;
import org.wso2.is.key.manager.core.tokenmgt.issuers.AbstractScopesIssuer;
import org.wso2.is.key.manager.core.tokenmgt.util.TokenMgtDataHolder;

/**
 * KeyManager core component to handle authentication
 */
@Component(
        name = "key.manager.core.component",
        immediate = true
)
public class KeyManagerCoreServiceComponent {

    private static final Log log = LogFactory.getLog(KeyManagerCoreServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {

        try {
            cxt.getBundleContext().registerService(AuthenticationHandler.class, new ExtendedISAuthHandler(), null);
            if (log.isDebugEnabled()) {
                log.debug("KeyManagerCoreService is activated");
            }

            //TokenMgtDataHolder.addScopesIssuer(roleBasedScopesIssuer.getPrefix(), roleBasedScopesIssuer);
            if (log.isDebugEnabled()) {
                log.debug("Permission based scope Issuer and Role based scope issuers are loaded.");
            }

            if (log.isDebugEnabled()) {
                log.debug("Identity API Key Mgt Bundle is started.");
            }

        } catch (Throwable e) {
            log.error(e.getMessage(), e);
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
            name = "registry.service",
            service = org.wso2.carbon.registry.core.service.RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService")
    protected void setRegistryService(RegistryService registryService) {

        ServiceReferenceHolder.getInstance().setRegistryService(registryService);
        if (log.isDebugEnabled()) {
            log.debug("Registry Service is set in the API KeyMgt bundle.");
        }
    }

    protected void unsetRegistryService(RegistryService registryService) {

        ServiceReferenceHolder.getInstance().setRegistryService(null);
        if (log.isDebugEnabled()) {
            log.debug("Registry Service is unset in the API KeyMgt bundle.");
        }
    }


    @Reference(
            name = "tenant.registryloader",
            service = org.wso2.carbon.registry.core.service.TenantRegistryLoader.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetTenantRegistryLoader")
    protected void setTenantRegistryLoader(TenantRegistryLoader tenantRegistryLoader) {
        ServiceReferenceHolder.getInstance().setTenantRegistryLoader(tenantRegistryLoader);
        if (log.isDebugEnabled()) {
            log.debug("Tenant Registry Loader is set in the API KeyMgt bundle.");
        }
    }

    protected void unsetTenantRegistryLoader(TenantRegistryLoader tenantRegistryLoader) {
        ServiceReferenceHolder.getInstance().setTenantRegistryLoader(null);
        if (log.isDebugEnabled()) {
            log.debug("Tenant Registry Loader is unset in the API KeyMgt bundle.");
        }
    }

    @Reference(
            name = "config.context.service",
            service = org.wso2.carbon.utils.ConfigurationContextService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationContextService")
    protected void setConfigurationContextService(ConfigurationContextService contextService) {
        ServiceReferenceHolder.setContextService(contextService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService contextService) {
        ServiceReferenceHolder.setContextService(null);
    }
}
