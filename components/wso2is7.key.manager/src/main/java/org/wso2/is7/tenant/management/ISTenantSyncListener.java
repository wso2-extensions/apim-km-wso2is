package org.wso2.is7.tenant.management;

import com.google.gson.Gson;
import feign.Feign;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIAdmin;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.dto.KeyManagerConfigurationDTO;
import org.wso2.carbon.apimgt.api.dto.KeyManagerPermissionConfigurationDTO;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.impl.APIAdminImpl;
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
import org.wso2.is7.client.internal.ServiceReferenceHolder;
import org.wso2.is7.client.model.TenantModel;
import org.wso2.is7.client.model.TenantResponseModel;
import org.wso2.is7.client.model.WSO2IS7TenantManagementClient;

import java.util.Arrays;
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

    private static final String MULTIVALUED = "multivalued";
    private static final String MULTIVALUED_STRING = "multivalued_";
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
                    .get(APIConstants.IS7TenantSharingConfigs.ENABLE_TENANT_SYNC));
            isAutoConfigureKeyManagerOfCurrentType = Boolean.parseBoolean(tenantSharingConfiguration.getProperties()
                    .get(APIConstants.IS7TenantSharingConfigs.AUTO_CONFIGURE_KEY_MANAGER));
            identityServerBaseUrl = getRefinedIdentityServerBaseUrl(tenantSharingConfiguration.getProperties()
                    .get(APIConstants.IS7TenantSharingConfigs.IDENTITY_SERVER_BASE_URL));

            if (isTenantSyncEnabled) {
                identityServerAdminUsername = tenantSharingConfiguration.getProperties()
                        .get(APIConstants.IS7TenantSharingConfigs.USERNAME);
                identityServerAdminPassword = tenantSharingConfiguration.getProperties()
                        .get(APIConstants.IS7TenantSharingConfigs.PASSWORD);
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
                    log.info("Endpoint for tenant management : " + tenantManagementEndpoint);
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
            TenantModel tenantInfo = new TenantModel();
            TenantModel.Owner tenantOwner = new TenantModel.Owner(
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
            log.info("Tenant sharing is not enabled, skipping tenant creation in Identity Server for tenant: "
                    + tenantDomain);
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

        APIAdmin apiAdmin = new APIAdminImpl();

        KeyManagerConfigurationDTO keyManagerConfigurationDTO =
                getKeyManagerConfigurationDTO(tenantInfoBean, identityServerBaseUrl);

        log.info("KeyManager ConfigurationDTO : " + new Gson().toJson(keyManagerConfigurationDTO));

        apiAdmin.addKeyManagerConfiguration(keyManagerConfigurationDTO);

        APIUtil.logAuditMessage(APIConstants.AuditLogConstants.KEY_MANAGER,
                new Gson().toJson(keyManagerConfigurationDTO),
                APIConstants.AuditLogConstants.CREATED, "reservedUserName");
    }

    public static KeyManagerConfigurationDTO getKeyManagerConfigurationDTO(TenantInfoBean tenantInfoBean,
                                                                           String identityServerBaseUrl) {
        String tenantDomain = tenantInfoBean.getTenantDomain();

        KeyManagerConfigurationDTO keyManagerConfigurationDTO = new KeyManagerConfigurationDTO();
        Map<String, String> endpoints = new HashMap<>();

        keyManagerConfigurationDTO.setName(APIConstants.KeyManager.DEFAULT_KEY_MANAGER);
        keyManagerConfigurationDTO.setDisplayName("IS7 as Default Key Manager");
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
        additionalProperties.put(APIConstants.KeyManager.IS7_AUTHENTICATION, APIConstants.KeyManager.IS7_MTLS);
        additionalProperties.put(APIConstants.KeyManager.IS7_MTLS, MULTIVALUED);
        additionalProperties.put("TenantDomain", tenantDomain);
        /* Add username of the user provided identity user, since currently it's required, for authorization of
         DCR call in IS side */
        additionalProperties.put(MULTIVALUED_STRING + APIConstants.KeyManager.IS7_MTLS,
                Arrays.asList(APIConstants.KeyManager.IS7_IDENTITY_USER, "ServerWide"));
        additionalProperties.put(APIConstants.KeyManager.IS7_IDENTITY_USER,
                tenantInfoBean.getAdmin() + "@" + tenantDomain);
        additionalProperties.put("api_resource_management_endpoint",
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/api/server/v1/api-resources");
        additionalProperties.put("is7_roles_endpoint", identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain
                + "/scim2/v2/Roles");
        additionalProperties.put("client_secret", "");

        //endpoints
        additionalProperties.put(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/api/identity/oauth2/dcr/v1.1/register");
        endpoints.put(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/api/identity/oauth2/dcr/v1.1/register");

        additionalProperties.put(APIConstants.KeyManager.INTROSPECTION_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/oauth2/introspect");
        endpoints.put(APIConstants.KeyManager.INTROSPECTION_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/oauth2/introspect");

        additionalProperties.put(APIConstants.KeyManager.TOKEN_ENDPOINT, identityServerBaseUrl +
                TENANT_PATH_PREFIX + tenantDomain +
                "/oauth2/token");
        endpoints.put(APIConstants.KeyManager.TOKEN_ENDPOINT, identityServerBaseUrl + TENANT_PATH_PREFIX +
                tenantDomain + "/oauth2/token");

        additionalProperties.put(APIConstants.KeyManager.DISPLAY_TOKEN_ENDPOINT, identityServerBaseUrl +
                TENANT_PATH_PREFIX + tenantDomain + "/oauth2/token");
        endpoints.put(APIConstants.KeyManager.DISPLAY_TOKEN_ENDPOINT, identityServerBaseUrl + TENANT_PATH_PREFIX +
                tenantDomain +
                "/oauth2/token");

        additionalProperties.put(APIConstants.KeyManager.REVOKE_ENDPOINT, identityServerBaseUrl + TENANT_PATH_PREFIX +
                tenantDomain + "/oauth2/revoke");
        endpoints.put(APIConstants.KeyManager.REVOKE_ENDPOINT, identityServerBaseUrl + TENANT_PATH_PREFIX +
                tenantDomain + "/oauth2/revoke");

        additionalProperties.put(APIConstants.KeyManager.DISPLAY_REVOKE_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/oauth2/revoke");
        endpoints.put(APIConstants.KeyManager.DISPLAY_REVOKE_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/oauth2/revoke");

        additionalProperties.put(APIConstants.KeyManager.USERINFO_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/scim2/Me");
        endpoints.put(APIConstants.KeyManager.USERINFO_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/scim2/Me");

        additionalProperties.put(APIConstants.KeyManager.AUTHORIZE_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/oauth2/authorize");
        endpoints.put(APIConstants.KeyManager.AUTHORIZE_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/oauth2/authorize");

        additionalProperties.put(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/api/identity/oauth2/v1.0/scopes");
        endpoints.put(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/api/identity/oauth2/v1.0/scopes");

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

        additionalProperties.put(APIConstants.KeyManager.ISSUER, identityServerBaseUrl + TENANT_PATH_PREFIX +
                tenantDomain + "/oauth2/token");

        // certificates
        additionalProperties.put(APIConstants.KeyManager.CERTIFICATE_TYPE,
                APIConstants.KeyManager.CERTIFICATE_TYPE_JWKS_ENDPOINT);
        additionalProperties.put(APIConstants.KeyManager.CERTIFICATE_VALUE,
                identityServerBaseUrl + TENANT_PATH_PREFIX + tenantDomain + "/oauth2/jwks");
        keyManagerConfigurationDTO.setEndpoints(endpoints);

        additionalProperties.put(APIConstants.KeyManager.ENABLE_OAUTH_APP_CREATION, true);
        additionalProperties.put(APIConstants.KeyManager.ENABLE_MAP_OAUTH_CONSUMER_APPS, true);
        additionalProperties.put(APIConstants.KeyManager.ENABLE_TOKEN_GENERATION, true);
        additionalProperties.put(APIConstants.KeyManager.SELF_VALIDATE_JWT, true);

        keyManagerConfigurationDTO.setAdditionalProperties(additionalProperties);
        return keyManagerConfigurationDTO;
    }


    @Override
    public void onTenantUpdate(TenantInfoBean tenantInfoBean) throws StratosException {
        String tenantDomain = tenantInfoBean.getTenantDomain();
        log.info("Tenant updated in API Manager: " + tenantDomain);

        if (isTenantSyncEnabled) {
            // To get Tenant Id, Status, Owner from IS
            TenantResponseModel tenantInfoByDomain = wso2IS7TenantManagementClient.getTenantByDomain(tenantDomain);

            // since owner id is intermittently dropped from above response
            //TODO:remove this API call after IS fixes https://github.com/wso2-enterprise/wso2-iam-internal/issues/3992
            TenantResponseModel.OwnerResponse ownersResponse =
                    wso2IS7TenantManagementClient.getTenantOwners(tenantInfoByDomain.getId()).get(0);

            TenantModel.OwnerPutModel tenantOwner = new TenantModel.OwnerPutModel(
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

        if (isTenantSyncEnabled) {
            String tenantDomain;
            try {
                tenantDomain = tenantManager.getDomain(tenantId);
            } catch (UserStoreException e) {
                log.error("Error while getting the tenant domain from ID: " + tenantId, e);
                throw new StratosException(e);
            }
            // To get Tenant Id, Status, Owner from IS
            TenantResponseModel tenantInfoByDomain = wso2IS7TenantManagementClient.getTenantByDomain(tenantDomain);

            if (tenantInfoByDomain.getLifecycleStatus().getActivated()) {
                log.info("Tenant is already activated in IS: " + tenantDomain);
                return;
            }
            TenantModel.TenantPutModel tenantPutModel = new TenantModel.TenantPutModel(true);
            wso2IS7TenantManagementClient.updateTenantStatus(
                    tenantInfoByDomain.getId(),
                    tenantPutModel
            );
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
            TenantResponseModel tenantInfoByDomain = wso2IS7TenantManagementClient.getTenantByDomain(tenantDomain);

            if (!tenantInfoByDomain.getLifecycleStatus().getActivated()) {
                log.info("Tenant is already de-activated in IS: " + tenantDomain);
                return;
            }
            TenantModel.TenantPutModel tenantPutModel = new TenantModel.TenantPutModel(false);
            wso2IS7TenantManagementClient.updateTenantStatus(
                    tenantInfoByDomain.getId(),
                    tenantPutModel
            );
            log.info("Tenant de-activated successfully in IS: " + tenantDomain);
        } else {
            log.info("Tenant sharing is not enabled, skipping tenant de-activation in Identity Server for " +
                    "APIM tenant ID: " + tenantId);
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
