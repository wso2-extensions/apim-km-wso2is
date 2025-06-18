package org.wso2.is7.tenant.management;

import com.google.gson.Gson;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIAdmin;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.ExceptionCodes;
import org.wso2.carbon.apimgt.api.dto.KeyManagerConfigurationDTO;
import org.wso2.carbon.apimgt.api.dto.KeyManagerPermissionConfigurationDTO;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.impl.APIAdminImpl;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.dto.TenantSharingConfigurationDTO;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.tenant.mgt.internal.TenantMgtServiceComponent;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.is7.client.internal.ServiceReferenceHolder;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * Listener class for Tenant management in IS
 */
public class ISTenantSyncListener implements TenantMgtListener {
    private static final Log log = LogFactory.getLog(ISTenantSyncListener.class);
    private static final String DEFAULT_KEY_MANAGER = "IS7_default_key_manager";
    private static final APIManagerConfiguration API_MANAGER_CONFIGURATION;

    static {
        API_MANAGER_CONFIGURATION = ServiceReferenceHolder.getInstance()
                .getAPIManagerConfigurationService().getAPIManagerConfiguration();
    }

    @Override
    public void onTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {
        String tenantDomain = tenantInfoBean.getTenantDomain();
        log.info("Tenant created in API Manager: " + tenantDomain);

        TenantSharingConfigurationDTO tenantSharingConfiguration =
                API_MANAGER_CONFIGURATION.getTenantSharingConfiguration();

        if (tenantSharingConfiguration.isIsEnabled()) {
            try {
                ISTenantManagementRestClient.createTenantInIS(
                        tenantInfoBean.getAdmin(),
                        tenantInfoBean.getAdminPassword(),
                        tenantInfoBean.getTenantDomain(),
                        tenantInfoBean.getFirstname(),
                        tenantInfoBean.getLastname(),
                        tenantInfoBean.getEmail(),
                        tenantSharingConfiguration.getReservedUserName(),
                        tenantSharingConfiguration.getReservedUserPassword()
                );
            } catch (IOException e) {
                log.error("Error while creating tenant in IS: " + tenantDomain, e);
                throw new StratosException(e);
            }
            log.info("Tenant created successfully in IS: " + tenantDomain);
            try {
                keyManagersPost(tenantInfoBean);
            } catch (APIManagementException e) {
                log.error("Error while creating Key Manager in API Manager for tenant: " + tenantDomain, e);
                throw new StratosException(e);
            }
        } else {
            log.info("Tenant sharing is not enabled, skipping tenant creation in Identity Server for tenant: "
                    + tenantDomain);
        }
    }

    private void keyManagersPost(TenantInfoBean tenantInfoBean) throws APIManagementException {

        APIAdmin apiAdmin = new APIAdminImpl();
        String organization = tenantInfoBean.getTenantDomain();
        try {
            KeyManagerConfigurationDTO keyManagerConfigurationDTO = getKeyManagerConfigurationDTO(tenantInfoBean);

            log.info("KeyManager ConfigurationDTO : " + new Gson().toJson(keyManagerConfigurationDTO));

            apiAdmin.addKeyManagerConfiguration(keyManagerConfigurationDTO);

            APIUtil.logAuditMessage(APIConstants.AuditLogConstants.KEY_MANAGER,
                    new Gson().toJson(keyManagerConfigurationDTO),
                    APIConstants.AuditLogConstants.CREATED, "reservedUserName");
        } catch (IllegalArgumentException e) {
            String error = "Error while storing Key Manager permission roles with name "
                    + DEFAULT_KEY_MANAGER + " in tenant " + organization;
            throw new APIManagementException(error, e, ExceptionCodes.ROLE_DOES_NOT_EXIST);
        }
    }

    public static KeyManagerConfigurationDTO getKeyManagerConfigurationDTO(TenantInfoBean tenantInfoBean) {
        String tenantDomain = tenantInfoBean.getTenantDomain();

        KeyManagerConfigurationDTO keyManagerConfigurationDTO = new KeyManagerConfigurationDTO();
        Map<String, String> endpoints = new HashMap<>();

        keyManagerConfigurationDTO.setName(DEFAULT_KEY_MANAGER);
        keyManagerConfigurationDTO.setDisplayName("IS7 Default Key Manager");
        keyManagerConfigurationDTO.setDescription("Default key manager created for IS7 when " +
                        "tenant synchronization is enabled");
        keyManagerConfigurationDTO.setEnabled(true);

        keyManagerConfigurationDTO.setType("WSO2-IS-7");
        keyManagerConfigurationDTO.setOrganization(tenantDomain);
        keyManagerConfigurationDTO.setTokenType(KeyManagerConfiguration.TokenType.DIRECT.toString());
        KeyManagerPermissionConfigurationDTO permissionsConfiguration = new KeyManagerPermissionConfigurationDTO();
        permissionsConfiguration.setPermissionType("PUBLIC");
        keyManagerConfigurationDTO.setPermissions(permissionsConfiguration);
        keyManagerConfigurationDTO.setAllowedOrganizations(Collections.singletonList("ALL"));

        /**
         * setting additional properties
         */
        // connector configuration
        Map<String, Object> additionalProperties = new HashMap();
        additionalProperties.put("Username", tenantInfoBean.getAdmin());
        additionalProperties.put("Password", tenantInfoBean.getAdminPassword());
        additionalProperties.put("api_resource_management_endpoint",
                "https://localhost:9444/api/server/v1/api-resources");
        additionalProperties.put("is7_roles_endpoint", "https://localhost:9444/scim2/v2/Roles");

        //endpoints
        additionalProperties.put(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT,
                "https://localhost:9444/api/identity/oauth2/dcr/v1.1/register");
        endpoints.put(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT,
                "https://localhost:9444/api/identity/oauth2/dcr/v1.1/register");

        additionalProperties.put(APIConstants.KeyManager.INTROSPECTION_ENDPOINT,
                "https://localhost:9444/oauth2/introspect");
        endpoints.put(APIConstants.KeyManager.INTROSPECTION_ENDPOINT,
                "https://localhost:9444/oauth2/introspect");

        additionalProperties.put(APIConstants.KeyManager.TOKEN_ENDPOINT, "https://localhost:9444/oauth2/token");
        endpoints.put(APIConstants.KeyManager.TOKEN_ENDPOINT, "https://localhost:9444/oauth2/token");

        additionalProperties.put(APIConstants.KeyManager.DISPLAY_TOKEN_ENDPOINT, "https://localhost:9444/oauth2/token");
        endpoints.put(APIConstants.KeyManager.DISPLAY_TOKEN_ENDPOINT, "https://localhost:9444/oauth2/token");

        additionalProperties.put(APIConstants.KeyManager.REVOKE_ENDPOINT, "https://localhost:9444/oauth2/revoke");
        endpoints.put(APIConstants.KeyManager.REVOKE_ENDPOINT, "https://localhost:9444/oauth2/revoke");

        additionalProperties.put(APIConstants.KeyManager.DISPLAY_REVOKE_ENDPOINT,
                "https://localhost:9444/oauth2/revoke");
        endpoints.put(APIConstants.KeyManager.DISPLAY_REVOKE_ENDPOINT,
                "https://localhost:9444/oauth2/revoke");

        additionalProperties.put(APIConstants.KeyManager.USERINFO_ENDPOINT,
                "https://localhost:9444/scim2/Me");
        endpoints.put(APIConstants.KeyManager.USERINFO_ENDPOINT,
                "https://localhost:9444/scim2/Me");

        additionalProperties.put(APIConstants.KeyManager.AUTHORIZE_ENDPOINT,
                "https://localhost:9444/oauth2/authorize");
        endpoints.put(APIConstants.KeyManager.AUTHORIZE_ENDPOINT,
                "https://localhost:9444/oauth2/authorize");

        additionalProperties.put(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT,
                "https://localhost:9444/api/identity/oauth2/v1.0/scopes");
        endpoints.put(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT,
                "https://localhost:9444/api/identity/oauth2/v1.0/scopes");

        //grant types
        additionalProperties.put(APIConstants.KeyManager.AVAILABLE_GRANT_TYPE,
                new String[]{
                        "refresh_token",
                        "urn:ietf:params:oauth:grant-type:saml2-bearer",
                        "password",
                        "client_credentials",
                        "iwa:ntlm",
                        "urn:ietf:params:oauth:grant-type:device_code",
                        "authorization_code",
                        "account_switch",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                        "organization_switch",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer"
                });

        additionalProperties.put(APIConstants.KeyManager.ISSUER, "https://localhost:9444/oauth2/token");

        // certificates
        additionalProperties.put(APIConstants.KeyManager.CERTIFICATE_VALUE,
                "https://localhost:9444/oauth2/jwks");
        additionalProperties.put(APIConstants.KeyManager.CERTIFICATE_TYPE,
                APIConstants.KeyManager.CERTIFICATE_TYPE_JWKS_ENDPOINT);

        keyManagerConfigurationDTO.setEndpoints(endpoints);

        additionalProperties.put(APIConstants.KeyManager.ENABLE_OAUTH_APP_CREATION, true);
        additionalProperties.put(APIConstants.KeyManager.ENABLE_MAP_OAUTH_CONSUMER_APPS, true);
        additionalProperties.put(APIConstants.KeyManager.ENABLE_TOKEN_GENERATION, true);
        additionalProperties.put(APIConstants.KeyManager.SELF_VALIDATE_JWT, true);

//        additionalProperties
//                    .put(APIConstants.KeyManager.TOKEN_FORMAT_STRING, new Gson().toJson(tokenValidationDTOList));
//        additionalProperties
//                    .put(APIConstants.KeyManager.CLAIM_MAPPING, new Gson().toJsonTree(claimMapping));
//        additionalProperties.put(APIConstants.KeyManager.CONSUMER_KEY_CLAIM, keyManagerDTO.getConsumerKeyClaim());
//        additionalProperties.put(APIConstants.KeyManager.SCOPES_CLAIM, keyManagerDTO.getScopesClaim());

        keyManagerConfigurationDTO.setAdditionalProperties(additionalProperties);
        return keyManagerConfigurationDTO;
    }


    @Override
    public void onTenantUpdate(TenantInfoBean tenantInfoBean) throws StratosException {
        String tenantDomain = tenantInfoBean.getTenantDomain();
        log.info("Tenant updated in API Manager: " + tenantDomain);
        TenantSharingConfigurationDTO tenantSharingConfiguration =
                API_MANAGER_CONFIGURATION.getTenantSharingConfiguration();
        if (tenantSharingConfiguration.isIsEnabled()) {
            try {
                ISTenantManagementRestClient.updateTenantInIS(
                        tenantDomain,
                        tenantInfoBean.getAdminPassword(),
                        tenantInfoBean.getFirstname(),
                        tenantInfoBean.getLastname(),
                        tenantInfoBean.getEmail(),
                        tenantSharingConfiguration.getReservedUserName(),
                        tenantSharingConfiguration.getReservedUserPassword()
                );
            } catch (IOException e) {
                log.error("Error while updating tenant in IS: " + tenantDomain, e);
                throw new StratosException(e);
            }
            log.info("Tenant updated successfully in IS: " + tenantDomain);
        } else {
            log.info("Tenant sharing is not enabled, skipping tenant update in Identity Server for tenant: "
                    + tenantDomain);
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
        TenantSharingConfigurationDTO tenantSharingConfiguration =
                API_MANAGER_CONFIGURATION.getTenantSharingConfiguration();
        if (tenantSharingConfiguration.isIsEnabled()) {
            String tenantDomain;
            try {
                tenantDomain = tenantManager.getDomain(tenantId);
            } catch (UserStoreException e) {
                log.error("Error while getting the tenant domain from ID: " + tenantId, e);
                throw new StratosException(e);
            }

            try {
                ISTenantManagementRestClient.updateTenantStatusInIS(tenantDomain, true,
                        tenantSharingConfiguration.getReservedUserName(),
                        tenantSharingConfiguration.getReservedUserPassword());
            } catch (IOException e) {
                log.error("Error while activating tenant in IS: " + tenantDomain, e);
                throw new StratosException(e);
            }
            log.info("Tenant activated successfully in IS: " + tenantDomain);
        } else {
            log.info("Tenant sharing is not enabled, skipping tenant activation in Identity Server for " +
                    "APIM tenant ID: " + tenantId);
        }
    }

    @Override
    public void onTenantDeactivation(int tenantId) throws StratosException {
        //should get tenant domain for the corresponding ID as the ID is not the same for IS side
        TenantManager tenantManager = TenantMgtServiceComponent.getTenantManager();
        log.info("Tenant deactivated in API Manager: " + tenantId);
        TenantSharingConfigurationDTO tenantSharingConfiguration =
                API_MANAGER_CONFIGURATION.getTenantSharingConfiguration();
        if (tenantSharingConfiguration.isIsEnabled()) {
            String tenantDomain;
            try {
                tenantDomain = tenantManager.getDomain(tenantId);
            } catch (UserStoreException e) {
                log.error("Error while getting the tenant domain from ID: " + tenantId, e);
                throw new StratosException(e);
            }
            try {
                ISTenantManagementRestClient.updateTenantStatusInIS(tenantDomain, false,
                        tenantSharingConfiguration.getReservedUserName(),
                        tenantSharingConfiguration.getReservedUserPassword());
            } catch (IOException e) {
                log.error("Error while deactivating tenant in IS: " + tenantId, e);
                throw new StratosException(e);
            }
            log.info("Tenant deactivated successfully in IS: " + tenantId);
        } else {
            log.info("Tenant sharing is not enabled, skipping tenant deactivation in Identity Server for APIM " +
                    "tenant ID: " + tenantId);
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
