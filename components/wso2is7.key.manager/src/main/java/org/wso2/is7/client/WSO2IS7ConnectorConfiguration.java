/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.is7.client;

import com.google.gson.Gson;
import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.APIAdmin;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.dto.KeyManagerConfigurationDTO;
import org.wso2.carbon.apimgt.api.dto.KeyManagerPermissionConfigurationDTO;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;
import org.wso2.carbon.apimgt.impl.APIAdminImpl;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.jwt.JWTValidatorImpl;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.context.PrivilegedCarbonContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Connector configuration for WSO2 Identity Server 7.
 */
@Component(
        name = "wso2is7.configuration.component",
        immediate = true,
        service = KeyManagerConnectorConfiguration.class
)
public class WSO2IS7ConnectorConfiguration implements KeyManagerConnectorConfiguration {

    @Override
    public String getImplementation() {
        return WSO2IS7KeyManager.class.getName();
    }

    @Override
    public String getJWTValidator() {
        return JWTValidatorImpl.class.getName();
    }

    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList.add(new ConfigurationDto("api_resource_management_endpoint",
                "WSO2 Identity Server 7 API Resource Management Endpoint", "input",
                String.format("E.g., %s/api/server/v1/api-resources",
                        org.wso2.carbon.apimgt.api.APIConstants.DEFAULT_KEY_MANAGER_HOST), "", true, false,
                Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto("is7_roles_endpoint",
                "WSO2 Identity Server 7 Roles Endpoint", "input",
                String.format("E.g., %s/scim2/v2/Roles",
                        org.wso2.carbon.apimgt.api.APIConstants.DEFAULT_KEY_MANAGER_HOST), "", true, false,
                Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto("enable_roles_creation",
                "Create roles in WSO2 Identity Server 7", "checkbox",
                "Create roles in WSO2 Identity Server 7, corresponding to the roles used in WSO2 API Manager.",
                "Enable", false, false, Collections.singletonList("Enable"), false));
        configurationDtoList.add(new ConfigurationDto("user_schema_cache_enabled",
                "Enable User Schema Caching", "checkbox",
                "Enable user schema caching, corresponding to the user schemas defined in IS 7.x",
                "Enable", false, false, Collections.singletonList("Enable"), false));
        return configurationDtoList;
    }

    @Override
    public List<ConfigurationDto> getAuthConfigurations() {

        List<ConfigurationDto> basicAuthValues = new ArrayList<>();
        basicAuthValues.add(new ConfigurationDto(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.USERNAME,
                "Username", "input", "Username of admin user", "", true,
                false, Collections.emptyList(), false));
        basicAuthValues.add(new ConfigurationDto(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.PASSWORD,
                "Password", "input", "Password of admin user", "", true,
                true, Collections.emptyList(), false));
        ConfigurationDto basicAuthConfigurationDto = new ConfigurationDto(
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.BASIC_AUTH,
                "Basic Authentication", "labelOnly", "Select to use basic authentication",
                "", false, false, basicAuthValues, true);

        List<ConfigurationDto> certBasedAuthValues = new ArrayList<>();
        certBasedAuthValues.add(new ConfigurationDto(
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.SERVERWIDE,
                "Server-Wide Certificate", "labelOnly",
                "Uses a globally trusted client certificate already configured on the server. " +
                        "No upload is required", "",
                false, false, Collections.emptyList(), false));

        certBasedAuthValues.add(new ConfigurationDto(
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.TENANTWIDE,
                "Tenant-Wide Certificate", "labelOnly",
                "Upload a dedicated certificate specifically for this tenant", "",
                false, false, Collections.singletonList(
                        new ConfigurationDto(
                                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.TENANTWIDE_CERTIFICATE,
                                "Add a new certificate", "certificate",
                                "Tenant wide certificate for mutual TLS authentication",
                                "", true, false, Collections.emptyList(), false)),
                false));
        ConfigurationDto certificateBasedAuthConfigurationDto = new ConfigurationDto(
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS,
                "MTLS Authentication", "labelOnly", "Select to use MTLS authentication",
                "", false, false, Arrays.asList(
                        new ConfigurationDto(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.IDENTITY_USER,
                                "Identity Username", "input",
                                "Username of an identity user who belongs to the same tenant domain. " +
                                        "This username links the client's mTLS identity and is required to " +
                                        "establish ownership and context for API operations.",
                                "", true, false, Collections.emptyList(), false),
                        new ConfigurationDto(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS_OPTIONS,
                                "Select a Certificate Type", "options",
                                "", "", true, false,
                                certBasedAuthValues, false)),
                true);

        List<ConfigurationDto> authValues = new ArrayList<>();
        authValues.add(basicAuthConfigurationDto);
        authValues.add(certificateBasedAuthConfigurationDto);

        return Collections.singletonList(new ConfigurationDto(
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.AUTHENTICATION,
                "Authentication Type", "dropdown", "Select the authentication type",
                "BasicAuth", true, false, authValues, false));
    }

    @Override
    public void processConnectorConfigurations(Map<String, Object> propertiesMap) {
        if (!propertiesMap.containsKey(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.AUTHENTICATION)) {
            // the data has the old config structure. Hence, need to set missing fields
            propertiesMap.put(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.AUTHENTICATION,
                    WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.BASIC_AUTH);
        }
    }

    @Override
    public List<String> validateAuthConfigurations(Map<String, Object> additionalProperties) {
        List<String> validationErrors = new ArrayList<>();
        if (WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.BASIC_AUTH.equals(
                additionalProperties.get(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.AUTHENTICATION))) {
            if (StringUtils.isEmpty(additionalProperties
                    .get(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.USERNAME).toString())) {
                validationErrors.add(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.USERNAME);
            }
            if (StringUtils.isEmpty(additionalProperties
                    .get(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.PASSWORD).toString())) {
                validationErrors.add(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.PASSWORD);
            }
        }
        if (WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS.equals(
                additionalProperties
                        .get(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.AUTHENTICATION))) {
            Object mtlsOptions = additionalProperties
                    .get(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS_OPTIONS);
            if (mtlsOptions == null ||
                    StringUtils.isEmpty(mtlsOptions.toString())) {
                validationErrors.add(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS_OPTIONS);
            }
            Object identityUser = additionalProperties
                    .get(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.IDENTITY_USER);
            if (identityUser == null || StringUtils.isEmpty(identityUser.toString())) {
                validationErrors.add(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.IDENTITY_USER);
            }
        }
        return validationErrors;
    }

    private KeyManagerConfigurationDTO getKeyManagerConfigurationDTO(Map<String, String> propertiesMap) {
        String tenantDomain = propertiesMap.get(APIConstants.TENANT_DOMAIN);
        String identityServerBaseUrl = propertiesMap.get(
                WSO2IS7KeyManagerConstants.IS7TenantSharingConfigs.IDENTITY_SERVER_BASE_URL);
        String tenantAdmin = propertiesMap.get(
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.IDENTITY_USER);
        String tenantPathPrefix = "t/";

        KeyManagerConfigurationDTO keyManagerConfigurationDTO = new KeyManagerConfigurationDTO();
        Map<String, String> endpoints = new HashMap<>();

        keyManagerConfigurationDTO.setName(APIConstants.KeyManager.DEFAULT_KEY_MANAGER);
        keyManagerConfigurationDTO.setDisplayName("IS7 as Default Key Manager");
        keyManagerConfigurationDTO.setDescription("Default key manager created for IS7 when " +
                "tenant synchronization is enabled");
        keyManagerConfigurationDTO.setEnabled(true);

        keyManagerConfigurationDTO.setType(WSO2IS7KeyManagerConstants.WSO2_IS7_TYPE);
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
        additionalProperties.put("TenantDomain", tenantDomain);
        additionalProperties.put(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.AUTHENTICATION,
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS);
        /* Add username of the user provided identity user, since currently it's required, for authorization of
         DCR call in IS side */
        additionalProperties.put(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.IDENTITY_USER,
                tenantAdmin + "@" + tenantDomain);
        additionalProperties.put(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS_OPTIONS,
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.SERVERWIDE);
        additionalProperties.put(
                WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.API_RESOURCE_MANAGEMENT_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/api/server/v1/api-resources");
        additionalProperties.put(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.ROLES_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain
                        + "/scim2/v2/Roles");
        additionalProperties.put("client_secret", "");

        //endpoints
        additionalProperties.put(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/api/identity/oauth2/dcr/v1.1/register");
        endpoints.put(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/api/identity/oauth2/dcr/v1.1/register");

        additionalProperties.put(APIConstants.KeyManager.INTROSPECTION_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/oauth2/introspect");
        endpoints.put(APIConstants.KeyManager.INTROSPECTION_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/oauth2/introspect");

        additionalProperties.put(APIConstants.KeyManager.TOKEN_ENDPOINT, identityServerBaseUrl +
                tenantPathPrefix + tenantDomain +
                "/oauth2/token");
        endpoints.put(APIConstants.KeyManager.TOKEN_ENDPOINT, identityServerBaseUrl + tenantPathPrefix +
                tenantDomain + "/oauth2/token");

        additionalProperties.put(APIConstants.KeyManager.DISPLAY_TOKEN_ENDPOINT, identityServerBaseUrl +
                tenantPathPrefix + tenantDomain + "/oauth2/token");
        endpoints.put(APIConstants.KeyManager.DISPLAY_TOKEN_ENDPOINT, identityServerBaseUrl + tenantPathPrefix +
                tenantDomain +
                "/oauth2/token");

        additionalProperties.put(APIConstants.KeyManager.REVOKE_ENDPOINT, identityServerBaseUrl + tenantPathPrefix +
                tenantDomain + "/oauth2/revoke");
        endpoints.put(APIConstants.KeyManager.REVOKE_ENDPOINT, identityServerBaseUrl + tenantPathPrefix +
                tenantDomain + "/oauth2/revoke");

        additionalProperties.put(APIConstants.KeyManager.DISPLAY_REVOKE_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/oauth2/revoke");
        endpoints.put(APIConstants.KeyManager.DISPLAY_REVOKE_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/oauth2/revoke");

        additionalProperties.put(APIConstants.KeyManager.USERINFO_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/scim2/Me");
        endpoints.put(APIConstants.KeyManager.USERINFO_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/scim2/Me");

        additionalProperties.put(APIConstants.KeyManager.AUTHORIZE_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/oauth2/authorize");
        endpoints.put(APIConstants.KeyManager.AUTHORIZE_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/oauth2/authorize");

        additionalProperties.put(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/api/identity/oauth2/v1.0/scopes");
        endpoints.put(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/api/identity/oauth2/v1.0/scopes");

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

        additionalProperties.put(APIConstants.KeyManager.ISSUER, identityServerBaseUrl + tenantPathPrefix +
                tenantDomain + "/oauth2/token");

        // certificates
        additionalProperties.put(APIConstants.KeyManager.CERTIFICATE_TYPE,
                APIConstants.KeyManager.CERTIFICATE_TYPE_JWKS_ENDPOINT);
        additionalProperties.put(APIConstants.KeyManager.CERTIFICATE_VALUE,
                identityServerBaseUrl + tenantPathPrefix + tenantDomain + "/oauth2/jwks");
        keyManagerConfigurationDTO.setEndpoints(endpoints);

        additionalProperties.put(APIConstants.KeyManager.ENABLE_OAUTH_APP_CREATION, true);
        additionalProperties.put(APIConstants.KeyManager.ENABLE_MAP_OAUTH_CONSUMER_APPS, true);
        additionalProperties.put(APIConstants.KeyManager.ENABLE_TOKEN_GENERATION, true);
        additionalProperties.put(APIConstants.KeyManager.SELF_VALIDATE_JWT, true);

        keyManagerConfigurationDTO.setAdditionalProperties(additionalProperties);
        return keyManagerConfigurationDTO;
    }

    @Override
    public boolean configureDefaultKeyManager(Map<String, String> propertiesMap) throws APIManagementException {
        APIAdmin apiAdmin = new APIAdminImpl();
        KeyManagerConfigurationDTO keyManagerConfigurationDTO =
                getKeyManagerConfigurationDTO(propertiesMap);

        apiAdmin.addKeyManagerConfiguration(keyManagerConfigurationDTO);

        APIUtil.logAuditMessage(APIConstants.AuditLogConstants.KEY_MANAGER,
                new Gson().toJson(propertiesMap),
                APIConstants.AuditLogConstants.CREATED,
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername());
        return true;
    }

    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {

        List<ConfigurationDto> applicationConfigurationsList = new ArrayList();
        applicationConfigurationsList
                .add(new ConfigurationDto(WSO2IS7KeyManagerConstants.APPLICATION_TOKEN_LIFETIME,
                        "Lifetime of the Application Token ", "input", "Type Lifetime of the Application Token " +
                        "in seconds ", APIConstants.KeyManager.NOT_APPLICABLE_VALUE, false, false,
                        Collections.EMPTY_LIST, false));
        applicationConfigurationsList
                .add(new ConfigurationDto(WSO2IS7KeyManagerConstants.USER_TOKEN_LIFETIME,
                        "Lifetime of the User Token ", "input", "Type Lifetime of the User Token " +
                        "in seconds ", APIConstants.KeyManager.NOT_APPLICABLE_VALUE, false, false,
                        Collections.EMPTY_LIST, false));
        applicationConfigurationsList
                .add(new ConfigurationDto(WSO2IS7KeyManagerConstants.REFRESH_TOKEN_LIFETIME,
                        "Lifetime of the Refresh Token ", "input", "Type Lifetime of the Refresh Token " +
                        "in seconds ", APIConstants.KeyManager.NOT_APPLICABLE_VALUE, false, false,
                        Collections.EMPTY_LIST, false));
        applicationConfigurationsList
                .add(new ConfigurationDto(WSO2IS7KeyManagerConstants.ID_TOKEN_LIFETIME,
                        "Lifetime of the ID Token", "input", "Type Lifetime of the ID Token " +
                        "in seconds ", APIConstants.KeyManager.NOT_APPLICABLE_VALUE, false, false,
                        Collections.EMPTY_LIST, false));

        ConfigurationDto configurationDtoPkceMandatory = new ConfigurationDto(WSO2IS7KeyManagerConstants.PKCE_MANDATORY,
                "Enable PKCE", "checkbox", "Enable PKCE", String.valueOf(false), false, false,
                Collections.EMPTY_LIST, false);
        applicationConfigurationsList.add(configurationDtoPkceMandatory);

        ConfigurationDto configurationDtoPkcePlainText =
                new ConfigurationDto(WSO2IS7KeyManagerConstants.PKCE_SUPPORT_PLAIN,
                        "Support PKCE Plain text", "checkbox", "S256 is recommended, plain text too can be used.",
                        String.valueOf(false), false, false, Collections.EMPTY_LIST, false);
        applicationConfigurationsList.add(configurationDtoPkcePlainText);

        ConfigurationDto configurationDtoBypassClientCredentials =
                new ConfigurationDto(WSO2IS7KeyManagerConstants.PUBLIC_CLIENT,
                        "Public client", "checkbox", "Allow authentication without the client secret.",
                        String.valueOf(false), false, false, Collections.EMPTY_LIST, false);
        applicationConfigurationsList.add(configurationDtoBypassClientCredentials);

        return applicationConfigurationsList;
    }

    @Override
    public String getType() {

        return WSO2IS7KeyManagerConstants.WSO2_IS7_TYPE;
    }

    @Override
    public String getDisplayName() {

        return WSO2IS7KeyManagerConstants.WSO2_IS7_DISPLAY_NAME;
    }

    @Override
    public String getDefaultScopesClaim() {

        return APIConstants.JwtTokenConstants.SCOPE;
    }

    @Override
    public String getDefaultConsumerKeyClaim() {

        return APIConstants.JwtTokenConstants.AUTHORIZED_PARTY;
    }

}
