/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.is.key.manager.operations.endpoint.dcr.service;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants.ErrorMessages;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;
import org.wso2.carbon.identity.oauth.dcr.util.DCRMUtils;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerSecretDTO;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ClientSecret;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ClientSecretGenerationRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplication;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplicationRegistrationRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplicationUpdateRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.util.ExtendedDCRMUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Extended DCRMService service is used to manage OAuth2 application registration.
 */
public class DCRMService {

    private static final Log log = LogFactory.getLog(DCRMService.class);
    public static final String OVERRIDE_SP_NAME = "override.sp.name";
    private static OAuthAdminService oAuthAdminService = new OAuthAdminService();
    private ApplicationManagementService appMgtService;

    private static final String AUTH_TYPE_OAUTH_2 = "oauth2";
    private static final String OAUTH_VERSION = "OAuth-2.0";
    private static final String GRANT_TYPE_SEPARATOR = " ";
    private static final String APP_DISPLAY_NAME = "DisplayName";
    private static Pattern clientIdRegexPattern = null;
    private static final String APPLICATION_SCOPES_PREFIX = "app_scopes_";

    public DCRMService() {

        appMgtService = ApplicationManagementService.getInstance();
    }

    /**
     * Create OAuth2/OIDC application.
     *
     * @param registrationRequest registrationRequest
     * @return ExtendedApplication
     * @throws DCRMException DCRMException
     */
    public ExtendedApplication registerApplication(ExtendedApplicationRegistrationRequest registrationRequest)
            throws DCRMException {

        return createOAuthApplication(registrationRequest);
    }

    /**
     * Update OAuth/OIDC application.
     *
     * @param updateRequest updateRequest
     * @param clientId clientId
     * @return ExtendedApplication
     * @throws DCRMException DCRMException
     */
    public ExtendedApplication updateApplication(ExtendedApplicationUpdateRequest updateRequest, String clientId) throws
            DCRMException {

        OAuthConsumerAppDTO appDTO = getApplicationById(clientId);
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String applicationOwner = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String overrideSpNameProp = System.getProperty(OVERRIDE_SP_NAME);
        boolean overrideSpName = StringUtils.isEmpty(overrideSpNameProp) || Boolean.parseBoolean(overrideSpNameProp);

        String clientName = overrideSpName ? updateRequest.getClientName() : appDTO.getApplicationName();

        // Update Service Provider
        ServiceProvider sp = getServiceProvider(appDTO.getApplicationName(), tenantDomain);
        if (sp == null) {
            throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.FAILED_TO_GET_SP,
                    appDTO.getApplicationName(), null);
        }
        // We are setting this to true in order to support cross tenant subscriptions.
        sp.setSaasApp(true);

        // Update service provider property list with display name, application scopes properties
        updateServiceProviderPropertyList(sp, updateRequest.getApplicationDisplayName(),
                updateRequest.getApplicationScopes());
        // Get application scopes from the service provider properties
        List<String> applicationScopes = getApplicationScopesFromSP(sp);

        if (StringUtils.isNotEmpty(clientName)) {
            // Regex validation of the application name.
            if (!DCRMUtils.isRegexValidated(clientName)) {
                throw DCRMUtils.generateClientException(ErrorMessages.BAD_REQUEST_INVALID_SP_NAME,
                        DCRMUtils.getSPValidatorRegex());
            }
            // Need to create a deep clone, since modifying the fields of the original object,
            // will modify the cached SP object.
            ServiceProvider clonedSP = ExtendedDCRMUtils.cloneServiceProvider(sp);
            clonedSP.setApplicationName(clientName);
            updateServiceProvider(clonedSP, tenantDomain, applicationOwner);
        }

        // Update application
        try {
            if (StringUtils.isNotEmpty(clientName)) {
                // Regex validation of the application name.
                if (!DCRMUtils.isRegexValidated(clientName)) {
                    throw DCRMUtils.generateClientException(ErrorMessages.BAD_REQUEST_INVALID_SP_NAME,
                            DCRMUtils.getSPValidatorRegex());
                }
                appDTO.setApplicationName(clientName);
            }
            if (!updateRequest.getGrantTypes().isEmpty()) {
                String grantType = StringUtils.join(updateRequest.getGrantTypes(), GRANT_TYPE_SEPARATOR);
                appDTO.setGrantTypes(grantType);
            }
            if (!updateRequest.getRedirectUris().isEmpty()) {
                String callbackUrl =
                        validateAndSetCallbackURIs(updateRequest.getRedirectUris(), updateRequest.getGrantTypes());
                appDTO.setCallbackUrl(callbackUrl);
            }
            if (updateRequest.getTokenType() != null) {
                appDTO.setTokenType(updateRequest.getTokenType());
            }
            if (StringUtils.isNotEmpty(updateRequest.getBackchannelLogoutUri())) {
                String backChannelLogoutUri = validateBackchannelLogoutURI(updateRequest.getBackchannelLogoutUri());
                appDTO.setBackChannelLogoutUrl(backChannelLogoutUri);
            }
            if (updateRequest.getApplicationAccessTokenLifeTime() != null) {
                appDTO.setApplicationAccessTokenExpiryTime(updateRequest.getApplicationAccessTokenLifeTime());
            }
            if (updateRequest.getUserAccessTokenLifeTime() != null) {
                appDTO.setUserAccessTokenExpiryTime(updateRequest.getUserAccessTokenLifeTime());
            }
            if (updateRequest.getRefreshTokenLifeTime() != null) {
                appDTO.setRefreshTokenExpiryTime(updateRequest.getRefreshTokenLifeTime());
            }
            if (updateRequest.getIdTokenLifeTime() != null) {
                appDTO.setIdTokenExpiryTime(updateRequest.getIdTokenLifeTime());
            }
            if (updateRequest.getPkceMandatory() != null) {
                appDTO.setPkceMandatory(updateRequest.getPkceMandatory());
            }
            if (updateRequest.getPkceSupportPlain() != null) {
                appDTO.setPkceSupportPlain(updateRequest.getPkceSupportPlain());
            }
            if (updateRequest.getBypassClientCredentials() != null) {
                appDTO.setBypassClientCredentials(updateRequest.getBypassClientCredentials());
            }
            oAuthAdminService.updateConsumerApplication(appDTO);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_UPDATE_APPLICATION, clientId, e);
        }

        return buildResponse(getApplicationById(clientId), applicationScopes);
    }

    /**
     * Update service provider property list
     *
     * @param sp                     Service provider
     * @param applicationDisplayName Display name of the application
     * @param applicationScopes      List of application scopes
     */
    private void updateServiceProviderPropertyList(ServiceProvider sp, String applicationDisplayName,
            List<String> applicationScopes) {

        // Retrieve existing service provider properties
        ServiceProviderProperty[] serviceProviderProperties = sp.getSpProperties();

        boolean isDisplayNameSet = Arrays.stream(serviceProviderProperties)
                .anyMatch(property -> property.getName().equals(APP_DISPLAY_NAME));
        if (!isDisplayNameSet) {
            // Append application display name related property
            // This property is used when displaying the app name within the consent page
            ServiceProviderProperty serviceProviderProperty = new ServiceProviderProperty();
            serviceProviderProperty.setName(APP_DISPLAY_NAME);
            serviceProviderProperty.setValue(applicationDisplayName);
            serviceProviderProperties = (ServiceProviderProperty[]) ArrayUtils.add(serviceProviderProperties,
                    serviceProviderProperty);
        }
        // Update application scopes related properties
        serviceProviderProperties = updateSPProperties(serviceProviderProperties, applicationScopes);

        // Update service provider property list
        sp.setSpProperties(serviceProviderProperties);
    }

    /**
     * Update service provider properties with application scopes.
     *
     * @param spProperties        ServiceProviderProperty array
     * @param applicationScopes   List of application scopes
     * @return Updated ServiceProviderProperty array
     */
    private ServiceProviderProperty[] updateSPProperties(ServiceProviderProperty[] spProperties,
            List<String> applicationScopes) {

        // Remove all application scopes and add the requested application scopes
        List<ServiceProviderProperty> updatedProperties = new ArrayList<>(Arrays.asList(spProperties));
        updatedProperties.removeIf(prop -> prop.getName().startsWith(APPLICATION_SCOPES_PREFIX));
        for (String scope : applicationScopes) {
            ServiceProviderProperty spProp = new ServiceProviderProperty();
            spProp.setName(APPLICATION_SCOPES_PREFIX + scope);
            spProp.setValue(scope);
            updatedProperties.add(spProp);
        }
        return updatedProperties.toArray(new ServiceProviderProperty[0]);
    }

    /**
     * Retrieve application scopes from the service provider properties.
     *
     * @param sp ServiceProvider object
     * @return List of application scopes
     */
    private List<String> getApplicationScopesFromSP(ServiceProvider sp) {
        List<String> applicationScopes = new ArrayList<>();
        ServiceProviderProperty[] spProperties = sp.getSpProperties();
        if (spProperties != null) {
            for (ServiceProviderProperty property : spProperties) {
                if (property.getName().startsWith(APPLICATION_SCOPES_PREFIX)) {
                    applicationScopes.add(property.getValue());
                }
            }
        }
        return applicationScopes;
    }

    /**
     * get the Application By Id
     *
     * @param clientId clientId
     * @return ExtendedApplication
     * @throws DCRMException DCRMException
     */
    public ExtendedApplication getApplication(String clientId) throws DCRMException {

        OAuthConsumerAppDTO dto = this.getApplicationById(clientId, true);
        // Application name is already checked in the getApplicationById method.
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        ServiceProvider sp = getServiceProvider(dto.getApplicationName(), tenantDomain);
        if (sp == null) {
            throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.FAILED_TO_GET_SP,
                    dto.getApplicationName(), null);
        }
        return this.buildResponse(dto, getApplicationScopesFromSP(sp));
    }

    /**
     * Delete OAuth application
     *
     * @param clientId clientId
     * @throws DCRMException DCRMException
     */
    public void deleteApplication(String clientId) throws DCRMException {

        OAuthConsumerAppDTO appDTO = this.getApplicationById(clientId);
        String applicationOwner = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        String spName;
        try {
            spName = appMgtService.getServiceProviderNameByClientId(appDTO.getOauthConsumerKey(),
                    "oauth2", tenantDomain);
        } catch (IdentityApplicationManagementException var7) {
            throw new DCRMException("Error while retrieving the service provider.", var7);
        }

        if (!StringUtils.equals(spName, "default")) {
            if (log.isDebugEnabled()) {
                log.debug("The application with consumer key: " + appDTO.getOauthConsumerKey() +
                        " has an association with the service provider: " + spName);
            }

            this.deleteServiceProvider(spName, tenantDomain, applicationOwner);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("The application with consumer key: " + appDTO.getOauthConsumerKey() +
                        " doesn't have an associated service provider.");
            }

            this.deleteOAuthApplicationWithoutAssociatedSP(appDTO, tenantDomain, applicationOwner);
        }

    }

    /**
     * Delete OAuth application when there is no associated service provider exists.
     *
     * @param appDTO       {@link OAuthConsumerAppDTO} object of the OAuth app to be deleted
     * @param tenantDomain Tenant Domain
     * @param username     User Name
     * @throws DCRMException DCRMException
     */
    private void deleteOAuthApplicationWithoutAssociatedSP(OAuthConsumerAppDTO appDTO, String tenantDomain,
                                                           String username) throws DCRMException {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Delete OAuth application with the consumer key: " + appDTO.getOauthConsumerKey());
            }
            oAuthAdminService.removeOAuthApplicationData(appDTO.getOauthConsumerKey());
        } catch (IdentityOAuthAdminException e) {
            throw new DCRMException("Error while deleting the OAuth application with consumer key: " +
                    appDTO.getOauthConsumerKey(), e);
        }

        try {
            if (log.isDebugEnabled()) {
                log.debug("Get service provider with application name: " + appDTO.getApplicationName());
            }
            ServiceProvider serviceProvider = appMgtService.getServiceProvider(appDTO
                    .getApplicationName(), tenantDomain);
            if (serviceProvider == null) {
                if (log.isDebugEnabled()) {
                    log.debug("There is no service provider exists with the name: " + appDTO.getApplicationName());
                }
            } else if (serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()
                    .length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Delete the service provider: " + serviceProvider.getApplicationName());
                }
                appMgtService.deleteApplication(serviceProvider.getApplicationName(), tenantDomain,
                        username);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Service provider with name: " + serviceProvider.getApplicationName() +
                            " can not be deleted since it has association with other application/s");
                }
            }
        } catch (IdentityApplicationManagementException e) {
            throw new DCRMException("Error while deleting the service provider with the name: " +
                    appDTO.getApplicationName(), e);
        }
    }

    /**
     * @param clientId clientId
     * @return OAuthConsumerAppDTO
     * @throws DCRMException DCRMException
     */
    private OAuthConsumerAppDTO getApplicationById(String clientId) throws DCRMException {

        return getApplicationById(clientId, true);
    }

    /**
     * get Application By Id
     *
     * @param clientId clientId
     * @param isApplicationRolePermissionRequired isApplicationRolePermissionRequired
     * @return OAuthConsumerAppDTO
     * @throws DCRMException DCRMException
     */
    private OAuthConsumerAppDTO getApplicationById(String clientId, boolean isApplicationRolePermissionRequired)
            throws DCRMException {

        if (StringUtils.isEmpty(clientId)) {
            String errorMessage = "Invalid client_id";
            throw DCRMUtils.generateClientException(
                    ErrorMessages.BAD_REQUEST_INVALID_INPUT, errorMessage);
        }

        try {
            OAuthConsumerAppDTO dto = oAuthAdminService.getOAuthApplicationData(clientId);

            if (dto.getApplicationName() != null) {
                PrivilegedCarbonContext.getThreadLocalCarbonContext().
                        setUsername(MultitenantUtils.getTenantAwareUsername(dto.getUsername()));
            }

            if (StringUtils.isEmpty(dto.getApplicationName())) {
                throw DCRMUtils.generateClientException(
                        ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID, clientId);
            } else if (isApplicationRolePermissionRequired && !isUserAuthorized(clientId)) {
                throw DCRMUtils.generateClientException(
                        ErrorMessages.FORBIDDEN_UNAUTHORIZED_USER, clientId);
            }
            return dto;
        } catch (IdentityOAuthAdminException e) {
            if (e.getCause() instanceof InvalidOAuthClientException) {
                throw DCRMUtils
                        .generateClientException(ErrorMessages.NOT_FOUND_APPLICATION_WITH_ID, clientId);
            }
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID, clientId, e);
        }
    }

    /**
     * create OAuthApplication
     *
     * @param registrationRequest RegistrationRequest
     * @return ExtendedApplication
     * @throws DCRMException DCRMException
     */
    private ExtendedApplication createOAuthApplication(ExtendedApplicationRegistrationRequest registrationRequest)
            throws DCRMException {

        String applicationOwner = registrationRequest.getApplicationOwner();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(applicationOwner);

        String spName = registrationRequest.getClientName();
        String templateName = registrationRequest.getSpTemplateName();

        // Regex validation of the application name.
        if (!DCRMUtils.isRegexValidated(spName)) {
            throw DCRMUtils.generateClientException(ErrorMessages.BAD_REQUEST_INVALID_SP_NAME,
                    DCRMUtils.getSPValidatorRegex());
        }

        // Check whether a service provider already exists for the name we are trying to register the OAuth app with.
        if (isServiceProviderExist(spName, tenantDomain)) {
            throw DCRMUtils.generateClientException(ErrorMessages.CONFLICT_EXISTING_APPLICATION, spName);
        }

        if (StringUtils.isNotEmpty(registrationRequest.getConsumerKey()) && isClientIdExist(
                registrationRequest.getConsumerKey())) {
            throw DCRMUtils.generateClientException(ErrorMessages.CONFLICT_EXISTING_CLIENT_ID,
                    registrationRequest.getConsumerKey());
        }

        // Create a service provider.
        ServiceProvider serviceProvider = createServiceProvider(applicationOwner, tenantDomain, spName, templateName);

        OAuthConsumerAppDTO createdApp;
        try {
            // Register the OAuth app.
            createdApp = createOAuthApp(registrationRequest, applicationOwner, tenantDomain, spName);
        } catch (DCRMException ex) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth app: " + spName + " registration failed in tenantDomain: " + tenantDomain + ". " +
                        "Deleting the service provider: " + spName + " to rollback.");
            }
            deleteServiceProvider(spName, tenantDomain, applicationOwner);
            throw ex;
        }

        // Update service provider property list with display name property and application scopes
        updateServiceProviderPropertyList(serviceProvider, registrationRequest.getApplicationDisplayName(),
                registrationRequest.getApplicationScopes());
        // Get application scopes from the service provider properties
        List<String> applicationScopes = getApplicationScopesFromSP(serviceProvider);

        try {
            updateServiceProviderWithOAuthAppDetails(serviceProvider, createdApp, applicationOwner, tenantDomain);
        } catch (DCRMException ex) {
            // Delete the OAuth app created. This will also remove the registered SP for the OAuth app.
            deleteApplication(createdApp.getOauthConsumerKey());
            throw ex;
        }
        return buildResponse(createdApp, applicationScopes);
    }

    /**
     * Build the response
     *
     * @param createdApp        createdApp
     * @param applicationScopes applicationScopes
     * @return ExtendedApplication
     */
    private ExtendedApplication buildResponse(OAuthConsumerAppDTO createdApp, List<String> applicationScopes) {

        List<String> redirectUrisList = new ArrayList<>();
        redirectUrisList.add(createdApp.getCallbackUrl());

        List<String> grantTypeList = new ArrayList<>();
        String[] grantTypes = createdApp.getGrantTypes().split(" ");
        Collections.addAll(grantTypeList, grantTypes);

        ExtendedApplication application = new ExtendedApplication();
        application.setClientName(createdApp.getApplicationName());
        application.setClientId(createdApp.getOauthConsumerKey());
        application.setClientSecret(createdApp.getOauthConsumerSecret());
        application.setRedirectUris(redirectUrisList);
        application.setGrantTypes(grantTypeList);
        application.setApplicationOwner(createdApp.getUsername());
        application.setApplicationAccessTokenLifeTime(createdApp.getApplicationAccessTokenExpiryTime());
        application.setUserAccessTokenLifeTime(createdApp.getUserAccessTokenExpiryTime());
        application.setRefreshTokenLifeTime(createdApp.getRefreshTokenExpiryTime());
        application.setIdTokenLifeTime(createdApp.getIdTokenExpiryTime());
        application.setPkceMandatory(createdApp.getPkceMandatory());
        application.setPkceSupportPlain(createdApp.getPkceSupportPlain());
        application.setBypassClientCredentials(createdApp.isBypassClientCredentials());
        application.setTokenType(createdApp.getTokenType());
        application.setApplicationScopes(applicationScopes);
        return application;
    }

    /**
     * update ServiceProvider With OAuthAppDetails
     *
     * @param serviceProvider serviceProvider
     * @param createdApp createdApp
     * @param applicationOwner applicationOwner
     * @param tenantDomain tenantDomain
     * @throws DCRMException DCRMException
     */
    private void updateServiceProviderWithOAuthAppDetails(ServiceProvider serviceProvider,
                                                          OAuthConsumerAppDTO createdApp,
                                                          String applicationOwner,
                                                          String tenantDomain) throws DCRMException {
        // Update created service provider, InboundAuthenticationConfig with OAuth application info.
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        List<InboundAuthenticationRequestConfig> inboundAuthenticationRequestConfigs = new ArrayList<>();

        InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig =
                new InboundAuthenticationRequestConfig();
        inboundAuthenticationRequestConfig.setInboundAuthKey(createdApp.getOauthConsumerKey());
        inboundAuthenticationRequestConfig.setInboundAuthType(AUTH_TYPE_OAUTH_2);
        inboundAuthenticationRequestConfigs.add(inboundAuthenticationRequestConfig);
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(inboundAuthenticationRequestConfigs
                .toArray(new InboundAuthenticationRequestConfig[0]));
        serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        //Set SaaS app option
        serviceProvider.setSaasApp(true);

        // Update the Service Provider app to add OAuthApp as an Inbound Authentication Config
        updateServiceProvider(serviceProvider, tenantDomain, applicationOwner);
    }

    /**
     *
     * @param registrationRequest registrationRequest
     * @param applicationOwner applicationOwner
     * @param tenantDomain tenantDomain
     * @param spName spName
     * @return OAuthConsumerAppDTO
     * @throws DCRMException DCRMException
     */
    private OAuthConsumerAppDTO createOAuthApp(ExtendedApplicationRegistrationRequest registrationRequest,
                                               String applicationOwner,
                                               String tenantDomain,
                                               String spName) throws DCRMException {
        // Then Create OAuthApp
        OAuthConsumerAppDTO oAuthConsumerApp = new OAuthConsumerAppDTO();
        oAuthConsumerApp.setApplicationName(spName);
        oAuthConsumerApp.setUsername(applicationOwner);
        oAuthConsumerApp.setCallbackUrl(
                validateAndSetCallbackURIs(registrationRequest.getRedirectUris(), registrationRequest.getGrantTypes()));
        String grantType = StringUtils.join(registrationRequest.getGrantTypes(), GRANT_TYPE_SEPARATOR);
        oAuthConsumerApp.setGrantTypes(grantType);
        oAuthConsumerApp.setOAuthVersion(OAUTH_VERSION);
        oAuthConsumerApp.setTokenType(registrationRequest.getTokenType());
        oAuthConsumerApp.setBackChannelLogoutUrl(
                validateBackchannelLogoutURI(registrationRequest.getBackchannelLogoutUri()));
        if (registrationRequest.getApplicationAccessTokenLifeTime() != null) {
            oAuthConsumerApp
                    .setApplicationAccessTokenExpiryTime(registrationRequest.getApplicationAccessTokenLifeTime());
        }
        if (registrationRequest.getUserAccessTokenLifeTime() != null) {
            oAuthConsumerApp.setUserAccessTokenExpiryTime(registrationRequest.getUserAccessTokenLifeTime());
        }
        if (registrationRequest.getRefreshTokenLifeTime() != null) {
            oAuthConsumerApp.setRefreshTokenExpiryTime(registrationRequest.getRefreshTokenLifeTime());
        }
        if (registrationRequest.getIdTokenLifeTime() != null) {
            oAuthConsumerApp.setIdTokenExpiryTime(registrationRequest.getIdTokenLifeTime());
        }
        if (StringUtils.isNotEmpty(registrationRequest.getConsumerKey())) {
            String clientIdRegex = OAuthServerConfiguration.getInstance().getClientIdValidationRegex();
            if (clientIdMatchesRegex(registrationRequest.getConsumerKey(), clientIdRegex)) {
                oAuthConsumerApp.setOauthConsumerKey(registrationRequest.getConsumerKey());
            } else {
                throw DCRMUtils
                        .generateClientException(ErrorMessages.BAD_REQUEST_CLIENT_ID_VIOLATES_PATTERN,
                                clientIdRegex);
            }
        }

        if (StringUtils.isNotEmpty(registrationRequest.getConsumerSecret())) {
            oAuthConsumerApp.setOauthConsumerSecret(registrationRequest.getConsumerSecret());
        }
        if (registrationRequest.getPkceMandatory() != null) {
            oAuthConsumerApp.setPkceMandatory(registrationRequest.getPkceMandatory());
        }
        if (registrationRequest.getPkceSupportPlain() != null) {
            oAuthConsumerApp.setPkceSupportPlain(registrationRequest.getPkceSupportPlain());
        }
        if (registrationRequest.getBypassClientCredentials() != null) {
            oAuthConsumerApp.setBypassClientCredentials(registrationRequest.getBypassClientCredentials());
        }
        if (log.isDebugEnabled()) {
            log.debug("Creating OAuth Application: " + spName + " in tenant: " + tenantDomain);
        }

        OAuthConsumerAppDTO createdApp;

        try {
            createdApp = oAuthAdminService.registerAndRetrieveOAuthApplicationData(oAuthConsumerApp);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_REGISTER_APPLICATION, spName, e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Created OAuth Application: " + spName + " in tenant: " + tenantDomain);
        }

        if (createdApp == null) {
            throw DCRMUtils.generateServerException(ErrorMessages.FAILED_TO_REGISTER_APPLICATION, spName);
        }
        return createdApp;
    }

    /**
     * Create ServiceProvider
     *
     * @param applicationOwner applicationOwner
     * @param tenantDomain tenantDomain
     * @param spName spName
     * @param templateName templateName
     * @return ServiceProvider
     * @throws DCRMException DCRMException
     */
    private ServiceProvider createServiceProvider(String applicationOwner, String tenantDomain,
                                                  String spName, String templateName) throws DCRMException {
        // Create the Service Provider
        ServiceProvider sp = new ServiceProvider();
        sp.setApplicationName(spName);
        User user = new User();
        user.setUserName(applicationOwner);
        user.setTenantDomain(tenantDomain);
        sp.setOwner(user);
        // We are setting this to true in order to support cross tenant subscriptions.
        sp.setSaasApp(true);
        sp.setDescription("Service Provider for application " + spName);

        createServiceProvider(sp, tenantDomain, applicationOwner, templateName);

        // Get created service provider.
        ServiceProvider clientSP = getServiceProvider(spName, tenantDomain);
        if (clientSP == null) {
            throw DCRMUtils.generateClientException(ErrorMessages.FAILED_TO_REGISTER_SP, spName);
        }
        return clientSP;
    }

    /**
     * Check whether servers provider exist with a given name in the tenant.
     *
     * @param serviceProviderName serviceProviderName
     * @param tenantDomain tenantDomain
     * @return isServiceProviderExist
     */
    private boolean isServiceProviderExist(String serviceProviderName, String tenantDomain) {

        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = getServiceProvider(serviceProviderName, tenantDomain);
        } catch (DCRMException e) {
            log.error(
                    "Error while retrieving service provider: " + serviceProviderName + " in tenant: " + tenantDomain);
        }

        return serviceProvider != null;
    }

    /**
     * Check whether the provided client id is exists.
     *
     * @param clientId client id.
     * @return true if application exists with the client id.
     * @throws DCRMException in case of failure.
     */
    private boolean isClientIdExist(String clientId) throws DCRMException {

        try {
            OAuthConsumerAppDTO dto = oAuthAdminService.getOAuthApplicationData(clientId);
            return dto != null && StringUtils.isNotBlank(dto.getApplicationName());
        } catch (IdentityOAuthAdminException e) {
            if (e.getCause() instanceof InvalidOAuthClientException) {
                return false;
            }
            throw DCRMUtils
                    .generateServerException(ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID, clientId, e);
        }
    }

    /**
     * Get ServiceProvider
     *
     * @param applicationName applicationName
     * @param tenantDomain tenantDomain
     * @return ServiceProvider
     * @throws DCRMException DCRMException
     */
    private ServiceProvider getServiceProvider(String applicationName, String tenantDomain) throws DCRMException {

        ServiceProvider serviceProvider;
        try {
            serviceProvider = appMgtService.getServiceProvider(applicationName, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_GET_SP, applicationName, e);
        }
        return serviceProvider;
    }

    /**
     * update Service Provider
     *
     * @param serviceProvider serviceProvider
     * @param tenantDomain tenantDomain
     * @param userName userName
     * @throws DCRMException DCRMException
     */
    private void updateServiceProvider(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws DCRMException {

        try {
            appMgtService.updateApplication(serviceProvider, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_UPDATE_SP, serviceProvider.getApplicationName(), e);
        }
    }

    /**
     * create ServiceProvider
     *
     * @param serviceProvider serviceProvider
     * @param tenantDomain tenantDomain
     * @param username username
     * @param templateName templateName
     * @throws DCRMException DCRMException
     */
    private void createServiceProvider(ServiceProvider serviceProvider, String tenantDomain, String username,
                                       String templateName) throws DCRMException {

        try {
            if (templateName != null) {
                boolean isTemplateExists = appMgtService.isExistingApplicationTemplate(templateName, tenantDomain);
                if (!isTemplateExists) {
                    throw DCRMUtils.generateClientException(ErrorMessages
                            .BAD_REQUEST_INVALID_SP_TEMPLATE_NAME, templateName);
                }
            }
            appMgtService.createApplicationWithTemplate(serviceProvider, tenantDomain, username, templateName);
        } catch (IdentityApplicationManagementException e) {
            String errorMessage =
                    "Error while creating service provider: " + serviceProvider.getApplicationName() +
                            " in tenant: " + tenantDomain;
            throw new DCRMException(ErrorCodes.BAD_REQUEST.toString(), errorMessage, e);
        }
    }

    /**
     * Delete service provider
     *
     * @param applicationName applicationName
     * @param tenantDomain tenantDomain
     * @param userName userName
     * @throws DCRMException DCRMException
     */
    private void deleteServiceProvider(String applicationName,
                                       String tenantDomain, String userName) throws DCRMException {

        try {
            appMgtService.deleteApplication(applicationName, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils
                    .generateServerException(ErrorMessages.FAILED_TO_DELETE_SP, applicationName, e);
        }
    }

    /**
     * validate and set CallbackURIs
     *
     * @param redirectUris redirectUris
     * @param grantTypes grantTypes
     * @return CallbackURIs
     * @throws DCRMException DCRMException
     */
    private String validateAndSetCallbackURIs(List<String> redirectUris, List<String> grantTypes) throws DCRMException {

        //TODO: After implement multi-urls to the oAuth application, we have to change this API call
        //TODO: need to validate before processing request
        if (redirectUris.size() == 0) {
            if (isRedirectURIMandatory(grantTypes)) {
                String errorMessage = "RedirectUris property must have at least one URI value when using " +
                        "Authorization code or implicit grant types.";
                throw DCRMUtils.generateClientException(
                        ErrorMessages.BAD_REQUEST_INVALID_INPUT, errorMessage);
            } else {
                return StringUtils.EMPTY;
            }
        } else if (redirectUris.size() == 1) {
            String redirectUri = redirectUris.get(0);
            if (StringUtils.equalsIgnoreCase(redirectUri, "null")) {
                return StringUtils.EMPTY;
            }
            // handle If callback url is provided as regexp=(url1|url2|..) format
            if (redirectUri.contains(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
                String[] uris = redirectUri.replace(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX, "")
                        .replace("(", "").replace(")", "").split("\\|");
                for (String uri : uris) {
                    if (!DCRMUtils.isRedirectionUriValid(uri)) {
                        throw DCRMUtils.generateClientException(
                                ErrorMessages.BAD_REQUEST_INVALID_REDIRECT_URI, redirectUri);
                    }
                }
                return redirectUri;
            } else {
                if (DCRMUtils.isRedirectionUriValid(redirectUri)) {
                    return redirectUri;
                } else {
                    throw DCRMUtils.generateClientException(
                            ErrorMessages.BAD_REQUEST_INVALID_REDIRECT_URI, redirectUri);
                }
            }
        } else {
            return OAuthConstants.CALLBACK_URL_REGEXP_PREFIX + createRegexPattern(redirectUris);
        }
    }

    /**
     * validate Backchannel LogoutURI
     *
     * @param backchannelLogoutUri backchannelLogoutUri
     * @return validation of Backchannel LogoutURI
     * @throws DCRMException DCRMException
     */
    private String validateBackchannelLogoutURI(String backchannelLogoutUri) throws DCRMException {

        if (DCRMUtils.isBackchannelLogoutUriValid(backchannelLogoutUri)) {
            return backchannelLogoutUri;
        } else {
            throw DCRMUtils.generateClientException(
                    ErrorMessages.BAD_REQUEST_INVALID_BACKCHANNEL_LOGOUT_URI, backchannelLogoutUri);
        }
    }

    /**
     * Check RedirectURI is Mandatory
     *
     * @param grantTypes grantTypes
     * @return isRedirectURIMandatory
     */
    private boolean isRedirectURIMandatory(List<String> grantTypes) {

        return grantTypes.contains(DCRConstants.GrantTypes.AUTHORIZATION_CODE) ||
                grantTypes.contains(DCRConstants.GrantTypes.IMPLICIT);
    }

    /**
     * create Regex Pattern
     *
     * @param redirectURIs redirectURIs
     * @return regex pattern
     * @throws DCRMException DCRMException
     */
    private String createRegexPattern(List<String> redirectURIs) throws DCRMException {

        StringBuilder regexPattern = new StringBuilder();
        for (String redirectURI : redirectURIs) {
            if (DCRMUtils.isRedirectionUriValid(redirectURI)) {
                if (regexPattern.length() > 0) {
                    regexPattern.append("|").append(redirectURI);
                } else {
                    regexPattern.append("(").append(redirectURI);
                }
            } else {
                throw DCRMUtils.generateClientException(
                        ErrorMessages.BAD_REQUEST_INVALID_REDIRECT_URI, redirectURI);
            }
        }
        if (regexPattern.length() > 0) {
            regexPattern.append(")");
        }
        return regexPattern.toString();
    }

    /**
     * Validate the user
     *
     * @param clientId clientId
     * @return user authorized or not
     * @throws DCRMServerException DCRMServerException
     */
    private boolean isUserAuthorized(String clientId) throws DCRMServerException {

        try {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            String spName = appMgtService.
                    getServiceProviderNameByClientId(clientId, DCRMConstants.OAUTH2, tenantDomain);
            String threadLocalUserName = CarbonContext.getThreadLocalCarbonContext().getUsername();
            return ApplicationMgtUtil.isUserAuthorized(spName, threadLocalUserName);
        } catch (IdentityApplicationManagementException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_GET_APPLICATION_BY_ID, clientId, e);
        }
    }

    /**
     * Validate client id according to the regex.
     *
     * @param clientId clientId
     * @param clientIdValidatorRegex clientIdValidatorRegex
     * @return validated or not
     */
    private static boolean clientIdMatchesRegex(String clientId, String clientIdValidatorRegex) {

        clientIdRegexPattern = Pattern.compile(clientIdValidatorRegex);
        return clientIdRegexPattern.matcher(clientId).matches();
    }

    /**
     * Get new application consumer secret
     *
     * @param clientId ClientId
     * @return ExtendedApplication
     * @throws DCRMServerException DCRMException
     */
    public ExtendedApplication getNewApplicationConsumerSecret(String clientId) throws DCRMServerException {

        OAuthConsumerAppDTO appDTO;
        try {
            appDTO = oAuthAdminService.updateAndRetrieveOauthSecretKey(clientId);
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            ServiceProvider sp = getServiceProvider(appDTO.getApplicationName(), tenantDomain);
            if (sp == null) {
                throw DCRMUtils.generateClientException(DCRMConstants.ErrorMessages.FAILED_TO_GET_SP,
                        appDTO.getApplicationName(), null);
            }
            return buildResponse(appDTO, getApplicationScopesFromSP(sp));
        } catch (IdentityOAuthAdminException | DCRMException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_UPDATE_APPLICATION, clientId, e);
        }
    }

    /**
     * Update the application owner
     *
     * @param applicationOwner ApplicationOwner
     * @param clientId ClientId
     * @return ExtendedApplication
     * @throws DCRMException DCRMException
     */
    public ExtendedApplication updateApplicationOwner(String applicationOwner, String clientId) throws
            DCRMException {

        OAuthConsumerAppDTO appDTO = getApplicationById(clientId);
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        // Update Service Provider
        ServiceProvider sp = getServiceProvider(appDTO.getApplicationName(), tenantDomain);
        sp.setOwner(User.getUserFromUserName(applicationOwner));

        updateServiceProvider(sp, tenantDomain, MultitenantUtils.getTenantAwareUsername(appDTO.getUsername()));
        appDTO.setUsername(applicationOwner);

        updateServiceProvider(sp, tenantDomain, MultitenantUtils.getTenantAwareUsername(applicationOwner));

        // Update application
        try {
            oAuthAdminService.updateConsumerApplication(appDTO);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_UPDATE_APPLICATION, clientId, e);
        }

        return buildResponse(getApplicationById(clientId), getApplicationScopesFromSP(sp));
    }

    /**
     * Creates a new client secret using the provided data.
     *
     * @param clientSecretCreationRequest the request containing client ID, optional description,
     *                                    and optional expiry time
     * @return the created {@link ClientSecret} object containing the generated secret details
     * @throws DCRMException if secret creation fails due to internal errors
     */
    public ClientSecret createClientSecret(ClientSecretGenerationRequest clientSecretGenerationRequest)
            throws DCRMException {

        OAuthConsumerSecretDTO oAuthConsumerSecretDTO = new OAuthConsumerSecretDTO();
        String clientId = clientSecretGenerationRequest.getClientId();
        oAuthConsumerSecretDTO.setClientId(clientId);
        oAuthConsumerSecretDTO.setDescription(clientSecretGenerationRequest.getDescription());
        if (clientSecretGenerationRequest.getExpiryAt() != null) {
            oAuthConsumerSecretDTO.setExpiresAt(clientSecretGenerationRequest.getExpiryAt());
        }
        OAuthConsumerSecretDTO createdSecret;
        try {
            createdSecret = oAuthAdminService.createClientSecret(oAuthConsumerSecretDTO);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_CREATE_CLIENT_SECRET, clientId, e);
        }

        return buildClientSecretResponse(createdSecret);
    }

    /**
     * Deletes an existing client secret.
     *
     * @param secretId the unique identifier of the client secret to be deleted
     * @throws DCRMException if secret deletion fails due to internal errors
     */
    public void deleteClientSecret(String secretId) throws DCRMException {

        try {
            oAuthAdminService.removeClientSecret(secretId);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(ErrorMessages.FAILED_TO_DELETE_CLIENT_SECRET, null, e);
        }
    }

    /**
     * Retrieves all secrets associated with the given client application.
     *
     * @param clientId the unique identifier of the client application
     * @return a list of {@link ClientSecret} objects for the specified client
     * @throws DCRMException if retrieving client secrets fails due to internal errors
     */
    public List<ClientSecret> getClientSecrets(String clientId) throws DCRMException {

        List<OAuthConsumerSecretDTO> consumerSecretDTOList;
        try {
            consumerSecretDTOList = oAuthAdminService.getClientSecrets(clientId);
        } catch (IdentityOAuthAdminException e) {
            throw DCRMUtils.generateServerException(
                    ErrorMessages.FAILED_TO_GET_CLIENT_SECRETS, clientId, e);
        }
        return buildClientSecretListResponse(consumerSecretDTOList);
    }

    /**
     * Builds a {@link ClientSecret} response object from the given
     * {@link OAuthConsumerSecretDTO}.
     *
     * @param createdSecret the {@link OAuthConsumerSecretDTO} containing secret details
     * @return a populated {@link ClientSecret} object
     */
    private ClientSecret buildClientSecretResponse(OAuthConsumerSecretDTO createdSecret) {

        ClientSecret clientSecret = new ClientSecret();
        clientSecret.setClientId(createdSecret.getClientId());
        clientSecret.setDescription(createdSecret.getDescription());
        if (createdSecret.getExpiresAt() == null) {
            clientSecret.setExpiryTime(0L);
        } else {
            clientSecret.setExpiryTime(createdSecret.getExpiresAt());
        }
        clientSecret.setSecretId(createdSecret.getSecretId());
        clientSecret.setClientSecret(createdSecret.getClientSecret());
        return clientSecret;
    }

    /**
     * Builds a list of {@link ClientSecret} response objects from a list of
     * {@link OAuthConsumerSecretDTO}.
     *
     * @param clientSecrets the list of {@link OAuthConsumerSecretDTO} objects
     * @return a list of {@link ClientSecret} response objects
     */
    private List<ClientSecret> buildClientSecretListResponse(List<OAuthConsumerSecretDTO> clientSecrets) {

        List<ClientSecret> clientSecretList = new ArrayList<>();
        for (OAuthConsumerSecretDTO secretDTO : clientSecrets) {
            clientSecretList.add(buildClientSecretResponse(secretDTO));
        }
        return clientSecretList;
    }
}
