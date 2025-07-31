/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com)
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.is7.tenant.management;

import feign.Feign;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.dto.TenantSharingConfigurationDTO;
import org.wso2.carbon.apimgt.impl.kmclient.ApacheFeignHttpClient;
import org.wso2.carbon.apimgt.impl.kmclient.KMClientErrorDecoder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.tenant.mgt.internal.TenantMgtServiceComponent;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.is7.client.WSO2IS7ConnectorConfiguration;
import org.wso2.is7.client.WSO2IS7KeyManagerConstants;
import org.wso2.is7.client.internal.ServiceReferenceHolder;
import org.wso2.is7.client.model.TenantInfo;
import org.wso2.is7.client.model.TenantOwnerInfo;
import org.wso2.is7.client.model.TenantOwnerResponse;
import org.wso2.is7.client.model.TenantOwnerUpdateInfo;
import org.wso2.is7.client.model.TenantResponse;
import org.wso2.is7.client.model.TenantStatusUpdateInfo;
import org.wso2.is7.client.model.WSO2IS7TenantManagementClient;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * Listener class for Tenant management in IS
 */
public class ISTenantSyncListener implements TenantMgtListener {
    private static final Log log = LogFactory.getLog(ISTenantSyncListener.class);
    private static final String TENANT_PATH_PREFIX = "t/";
    private static final String TENANT_MANAGEMENT_API_PATH = "api/server/v1";
    private static final APIManagerConfiguration apiManagerConfiguration;
    private WSO2IS7TenantManagementClient wso2IS7TenantManagementClient;
    TenantSharingConfigurationDTO tenantSharingConfiguration;
    private String identityServerBaseUrl;
    private boolean isTenantSyncEnabled = false;
    private String identityServerAdminUsername;
    private String identityServerAdminPassword;
    boolean isAutoConfigureKeyManagerOfCurrentType = false;
    boolean skipCreateDefaultResidentKm = false;

    static {
        apiManagerConfiguration = ServiceReferenceHolder.getInstance()
                .getAPIManagerConfigurationService().getAPIManagerConfiguration();
    }

    public ISTenantSyncListener()  {
        initializeTenantManagementClient();
    }

     private void initializeTenantManagementClient() {
        tenantSharingConfiguration = apiManagerConfiguration
                .getTenantSharingConfiguration(APIConstants.KeyManager.WSO2_IS7_KEY_MANAGER_TYPE);

        skipCreateDefaultResidentKm = Boolean.parseBoolean(apiManagerConfiguration
                .getFirstProperty(APIConstants.SKIP_CREATE_RESIDENT_KEY_MANAGER));

        if (tenantSharingConfiguration != null && tenantSharingConfiguration.getProperties() != null) {
            isTenantSyncEnabled = Boolean.parseBoolean(tenantSharingConfiguration.getProperties()
                    .get(WSO2IS7KeyManagerConstants.IS7TenantSharingConfigs.ENABLE_TENANT_SYNC));
            isAutoConfigureKeyManagerOfCurrentType = Boolean.parseBoolean(tenantSharingConfiguration.getProperties()
                    .get(WSO2IS7KeyManagerConstants.IS7TenantSharingConfigs.AUTO_CONFIGURE_KEY_MANAGER));
            identityServerBaseUrl = getRefinedIdentityServerBaseUrl(tenantSharingConfiguration.getProperties()
                    .get(WSO2IS7KeyManagerConstants.IS7TenantSharingConfigs.IDENTITY_SERVER_BASE_URL));

            if (isTenantSyncEnabled) {
                identityServerAdminUsername = tenantSharingConfiguration.getProperties()
                        .get(WSO2IS7KeyManagerConstants.IS7TenantSharingConfigs.USERNAME);
                identityServerAdminPassword = tenantSharingConfiguration.getProperties()
                        .get(WSO2IS7KeyManagerConstants.IS7TenantSharingConfigs.PASSWORD);
                String tenantManagementEndpoint = identityServerBaseUrl + TENANT_MANAGEMENT_API_PATH;

                try {
                    wso2IS7TenantManagementClient = Feign.builder()
                            .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(tenantManagementEndpoint)))
                            .encoder(new GsonEncoder())
                            .decoder(new GsonDecoder())
                            .logger(new Slf4jLogger())
                            .requestInterceptor(new BasicAuthRequestInterceptor(identityServerAdminUsername,
                                    identityServerAdminPassword))
                            .errorDecoder(new KMClientErrorDecoder())
                            .target(WSO2IS7TenantManagementClient.class, tenantManagementEndpoint);
                } catch (Exception e) {
                    log.error("Error initializing Feign client for tenant management: " + e.getMessage(), e);
                    // Optionally, set a flag to indicate the client is not initialized
                    wso2IS7TenantManagementClient = null;
                }
            }
        }
    }

    private String getRefinedIdentityServerBaseUrl (String identityServerBaseUrl) {
        if (!identityServerBaseUrl.endsWith("/")) {
            identityServerBaseUrl += "/";
        }
        return identityServerBaseUrl;
    }

    @Override
    public void onTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {
        String tenantDomain = tenantInfoBean.getTenantDomain();
        log.info("Tenant created in API Manager: " + tenantDomain);

        if (isTenantSyncEnabled) {
            TenantInfo tenantInfo = new TenantInfo();
            TenantOwnerInfo tenantOwner = new TenantOwnerInfo(
                    tenantInfoBean.getAdmin(),
                    tenantInfoBean.getAdminPassword(),
                    tenantInfoBean.getEmail(),
                    tenantInfoBean.getFirstname(),
                    tenantInfoBean.getLastname(),
                    null,
                    null
            );
            tenantInfo.setDomain(tenantDomain);
            tenantInfo.setOwners(Collections.singletonList(tenantOwner));
            wso2IS7TenantManagementClient.createTenant(tenantInfo);
            log.info("Tenant created successfully in IS: " + tenantDomain);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Tenant sharing is not enabled, skipping tenant creation in Identity Server for tenant: "
                        + tenantDomain);
            }
        }

        try {
            //cannot create another km with name Resident, if resident km is already there
            if (skipCreateDefaultResidentKm && isAutoConfigureKeyManagerOfCurrentType) {
                keyManagersPost(tenantInfoBean, identityServerBaseUrl);
            }
        } catch (APIManagementException e) {
            log.error("Error while creating Key Manager in API Manager for tenant: " + tenantDomain, e);
            throw new StratosException(e);
        }
    }

    private void keyManagersPost(TenantInfoBean tenantInfoBean, String identityServerBaseUrl)
            throws APIManagementException {

        Map<String, String> connectorPropertiesMap = new HashMap();
        connectorPropertiesMap.put(APIConstants.TENANT_DOMAIN, tenantInfoBean.getTenantDomain());
        connectorPropertiesMap.put(WSO2IS7KeyManagerConstants.IS7TenantSharingConfigs.IDENTITY_SERVER_BASE_URL,
                identityServerBaseUrl);
        connectorPropertiesMap.put(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.USERNAME,
                tenantInfoBean.getAdmin());
        WSO2IS7ConnectorConfiguration wso2IS7ConnectorConfiguration = new WSO2IS7ConnectorConfiguration();
        wso2IS7ConnectorConfiguration.configureDefaultKeyManager(connectorPropertiesMap);
    }

    @Override
    public void onTenantUpdate(TenantInfoBean tenantInfoBean) throws StratosException {
        String tenantDomain = tenantInfoBean.getTenantDomain();
        log.info("Tenant updated in API Manager: " + tenantDomain);

        if (isTenantSyncEnabled) {
            // To get Tenant Id, Status, Owner from IS
            TenantResponse tenantInfoByDomain = wso2IS7TenantManagementClient.getTenantByDomain(tenantDomain);

            // since owner id is intermittently dropped from above response
            //TODO:remove this API call after IS fixes https://github.com/wso2-enterprise/wso2-iam-internal/issues/3992
            TenantOwnerResponse ownersResponse =
                    wso2IS7TenantManagementClient.getTenantOwners(tenantInfoByDomain.getId()).get(0);

            TenantOwnerUpdateInfo tenantOwner = new TenantOwnerUpdateInfo(
                    tenantInfoBean.getEmail(),
                    tenantInfoBean.getAdminPassword(),
                    tenantInfoBean.getFirstname(),
                    tenantInfoBean.getLastname(),
                    null
            );
            wso2IS7TenantManagementClient.updateTenantOwner(tenantInfoByDomain.getId(), ownersResponse.getId(),
                    tenantOwner);
            log.info("Tenant updated successfully in IS: " + tenantDomain);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Tenant sharing is not enabled, skipping tenant update in Identity Server for tenant: "
                        + tenantDomain);
            }
        }
    }

    @Override
    public void onTenantDelete(int i) {

    }

    @Override
    public void onTenantRename(int i, String s, String s1) throws StratosException {

    }

    @Override
    public void onTenantInitialActivation(int i) throws StratosException {

    }

    @Override
    public void onTenantActivation(int tenantId) throws StratosException {
        //should get tenant domain for the corresponding ID as the ID is not the same for IS side
        TenantManager tenantManager = TenantMgtServiceComponent.getTenantManager();
        log.info("Tenant activated in API Manager: " + tenantId);

        if (isTenantSyncEnabled) {
            String tenantDomain;
            try {
                tenantDomain = tenantManager.getDomain(tenantId);
            } catch (UserStoreException e) {
                log.error("Error while getting the tenant domain from ID: " + tenantId, e);
                throw new StratosException(e);
            }
            // To get Tenant Id, Status, Owner from IS
            TenantResponse tenantInfoByDomain = wso2IS7TenantManagementClient.getTenantByDomain(tenantDomain);

            if (tenantInfoByDomain.getLifecycleStatus().getActivated()) {
                log.info("Tenant is already activated in IS: " + tenantDomain);
                return;
            }
            TenantStatusUpdateInfo tenantStatusUpdateInfo = new TenantStatusUpdateInfo(true);
            wso2IS7TenantManagementClient.updateTenantStatus(
                    tenantInfoByDomain.getId(),
                    tenantStatusUpdateInfo
            );
            log.info("Tenant activated successfully in IS: " + tenantDomain);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Tenant sharing is not enabled, skipping tenant activation in Identity Server for " +
                        "APIM tenant ID: " + tenantId);
            }
        }
    }

    @Override
    public void onTenantDeactivation(int tenantId) throws StratosException {
        //should get tenant domain for the corresponding ID as the ID is not the same for IS side
        TenantManager tenantManager = TenantMgtServiceComponent.getTenantManager();
        log.info("Tenant activated in API Manager: " + tenantId);

        if (isTenantSyncEnabled) {
            String tenantDomain;
            try {
                tenantDomain = tenantManager.getDomain(tenantId);
            } catch (UserStoreException e) {
                log.error("Error while getting the tenant domain from ID: " + tenantId, e);
                throw new StratosException(e);
            }
            // To get Tenant Id, Status, Owner from IS
            TenantResponse tenantInfoByDomain = wso2IS7TenantManagementClient.getTenantByDomain(tenantDomain);

            if (!tenantInfoByDomain.getLifecycleStatus().getActivated()) {
                log.info("Tenant is already de-activated in IS: " + tenantDomain);
                return;
            }
            TenantStatusUpdateInfo tenantStatusUpdateInfo = new TenantStatusUpdateInfo(false);
            wso2IS7TenantManagementClient.updateTenantStatus(
                    tenantInfoByDomain.getId(),
                    tenantStatusUpdateInfo
            );
            log.info("Tenant de-activated successfully in IS: " + tenantDomain);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Tenant sharing is not enabled, skipping tenant de-activation in Identity Server for " +
                        "APIM tenant ID: " + tenantId);
            }
        }
    }

    @Override
    public void onSubscriptionPlanChange(int i, String s, String s1) throws StratosException {

    }

    @Override
    public int getListenerOrder() {
        return 0;
    }

    @Override
    public void onPreDelete(int i) throws StratosException {

    }

    @Override
    public void onPreTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {
        TenantMgtListener.super.onPreTenantCreate(tenantInfoBean);
    }

    @Override
    public void onPostDelete(int tenantId, String tenantUuid, String adminUserUuid) throws StratosException {
        TenantMgtListener.super.onPostDelete(tenantId, tenantUuid, adminUserUuid);
    }

}
