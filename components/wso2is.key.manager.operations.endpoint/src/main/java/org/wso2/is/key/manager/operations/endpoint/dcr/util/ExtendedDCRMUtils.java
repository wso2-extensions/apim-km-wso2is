/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.is.key.manager.operations.endpoint.dcr.util;

import com.google.gson.Gson;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.util.DCRMUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ClientSecret;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ClientSecretGenerationRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplication;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplicationRegistrationRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplicationUpdateRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.exception.DCRMEndpointException;
import org.wso2.is.key.manager.operations.endpoint.dto.ApplicationDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretGenerationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretListDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretResponseDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.RegistrationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.UpdateRequestDTO;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.ws.rs.core.Response;

/**
 * Util class used for OAuth DCRM.
 */
public class ExtendedDCRMUtils extends  DCRMUtils {

    private static final String CONFLICT_STATUS = "CONFLICT_";
    private static final String BAD_REQUEST_STATUS = "BAD_REQUEST_";
    private static final String NOT_FOUND_STATUS = "NOT_FOUND_";
    private static final String FORBIDDEN_STATUS = "FORBIDDEN_";
    private static final String MULTIPLE_CLIENT_SECRETS_ENABLED = "OAuth.MultipleClientSecrets.Enable";

    public static ExtendedApplicationRegistrationRequest getApplicationRegistrationRequest(
            RegistrationRequestDTO registrationRequestDTO) {

        ExtendedApplicationRegistrationRequest appRegistrationRequest = new ExtendedApplicationRegistrationRequest();
        appRegistrationRequest.setClientName(registrationRequestDTO.getClientName());
        appRegistrationRequest.setRedirectUris(registrationRequestDTO.getRedirectUris());
        appRegistrationRequest.setGrantTypes(registrationRequestDTO.getGrantTypes());
        appRegistrationRequest.setTokenType(registrationRequestDTO.getTokenTypeExtension());
        appRegistrationRequest.setApplicationOwner(registrationRequestDTO.getExtApplicationOwner());
        appRegistrationRequest.setConsumerKey(registrationRequestDTO.getExtParamClientId());
        appRegistrationRequest.setConsumerSecret(registrationRequestDTO.getExtParamClientSecret());
        appRegistrationRequest.setSpTemplateName(registrationRequestDTO.getExtParamSpTemplate());
        appRegistrationRequest.setBackchannelLogoutUri(registrationRequestDTO.getBackchannelLogoutUri());
        appRegistrationRequest
                .setApplicationAccessTokenLifeTime(registrationRequestDTO.getExtApplicationTokenLifetime());
        appRegistrationRequest.setUserAccessTokenLifeTime(registrationRequestDTO.getExtUserTokenLifetime());
        appRegistrationRequest.setRefreshTokenLifeTime(registrationRequestDTO.getExtRefreshTokenLifetime());
        appRegistrationRequest.setIdTokenLifeTime(registrationRequestDTO.getExtIdTokenLifetime());
        appRegistrationRequest.setApplicationDisplayName(registrationRequestDTO.getApplicationDisplayName());
        appRegistrationRequest.setPkceMandatory(registrationRequestDTO.isPkceMandatory());
        appRegistrationRequest.setPkceSupportPlain(registrationRequestDTO.isPkceSupportPlain());
        appRegistrationRequest.setBypassClientCredentials(registrationRequestDTO.isBypassClientCredentials());
        appRegistrationRequest.setApplicationScopes(registrationRequestDTO.getApplicationScopes());
        if (ExtendedDCRMUtils.isMultipleClientSecretsEnabled()) {
            appRegistrationRequest.setSecretDescription(registrationRequestDTO.getExtClientSecretDescription());
            if (registrationRequestDTO.getExtClientSecretExpiresIn() != null) {
                appRegistrationRequest.setSecretExpiryTime(
                        calculateExpiresAt(registrationRequestDTO.getExtClientSecretExpiresIn()));
            }
        }
        return appRegistrationRequest;

    }

    public static ExtendedApplicationUpdateRequest getApplicationUpdateRequest(UpdateRequestDTO updateRequestDTO) {

        ExtendedApplicationUpdateRequest applicationUpdateRequest = new ExtendedApplicationUpdateRequest();
        applicationUpdateRequest.setClientName(updateRequestDTO.getClientName());
        applicationUpdateRequest.setRedirectUris(updateRequestDTO.getRedirectUris());
        applicationUpdateRequest.setGrantTypes(updateRequestDTO.getGrantTypes());
        applicationUpdateRequest.setTokenType(updateRequestDTO.getTokenTypeExtension());
        applicationUpdateRequest.setBackchannelLogoutUri(updateRequestDTO.getBackchannelLogoutUri());
        applicationUpdateRequest
                .setApplicationAccessTokenLifeTime(updateRequestDTO.getExtApplicationTokenLifetime());
        applicationUpdateRequest.setUserAccessTokenLifeTime(updateRequestDTO.getExtUserTokenLifetime());
        applicationUpdateRequest.setRefreshTokenLifeTime(updateRequestDTO.getExtRefreshTokenLifetime());
        applicationUpdateRequest.setIdTokenLifeTime(updateRequestDTO.getExtIdTokenLifetime());
        applicationUpdateRequest.setApplicationDisplayName(updateRequestDTO.getApplicationDisplayName());
        applicationUpdateRequest.setPkceMandatory(updateRequestDTO.isPkceMandatory());
        applicationUpdateRequest.setPkceSupportPlain(updateRequestDTO.isPkceSupportPlain());
        applicationUpdateRequest.setBypassClientCredentials(updateRequestDTO.isBypassClientCredentials());
        applicationUpdateRequest.setApplicationScopes(updateRequestDTO.getApplicationScopes());
        return applicationUpdateRequest;

    }

    public static void handleErrorResponse(DCRMException dcrmException, Log log) throws DCRMEndpointException {

        String errorCode = dcrmException.getErrorCode();
        Response.Status status = Response.Status.INTERNAL_SERVER_ERROR;
        boolean isStatusOnly = true;
        if (errorCode != null) {
            if (errorCode.startsWith(CONFLICT_STATUS)) {
                status = Response.Status.BAD_REQUEST;
                isStatusOnly = false;
            } else if (errorCode.startsWith(BAD_REQUEST_STATUS)) {
                status = Response.Status.BAD_REQUEST;
                isStatusOnly = false;
            } else if (errorCode.startsWith(NOT_FOUND_STATUS)) {
                status = Response.Status.UNAUTHORIZED;
            } else if (errorCode.startsWith(FORBIDDEN_STATUS)) {
                status = Response.Status.FORBIDDEN;
            }
        }
        throw buildDCRMEndpointException(status, errorCode, dcrmException.getMessage(), isStatusOnly);
    }

    /**
     * Logs the error, builds a DCRMEndpointException with specified details and throws it.
     *
     * @param status    response status
     * @param throwable throwable
     * @throws DCRMEndpointException DCRMEndpointException
     */
    public static void handleErrorResponse(Response.Status status, Throwable throwable,
                                           boolean isServerException, Log log)
            throws DCRMEndpointException {

        String errorCode;
        if (throwable instanceof DCRMException) {
            errorCode = ((DCRMException) throwable).getErrorCode();
        } else {
            errorCode = DCRMConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.toString();
        }

        if (isServerException) {
            if (throwable == null) {
                log.error(status.getReasonPhrase());
            } else {
                log.error(status.getReasonPhrase(), throwable);
            }
        }
        throw buildDCRMEndpointException(status, errorCode, throwable == null ? "" : throwable.getMessage(),
                isServerException);
    }

    /**
     * Logs the error, builds a DCRMEndpointException with specified details and throws it.
     *
     * @param status      response status
     * @param code        error code
     * @param message     error message
     * @param description error description
     * @throws DCRMEndpointException DCRMEndpointException
     */
    public static void handleErrorResponse(Response.Status status, String code, String message, String description)
            throws DCRMEndpointException {

        throw buildDCRMEndpointException(status, code, message, description);
    }

    /**
     * Validate grant types of application with the authorized grant types of toml configuration
     *
     * @param requestedGrantTypes List of requested grant types
     * @return validGrantTypes valid grant types among the requested ones
     */
    public static List<String> validateGrantTypes(List<String> requestedGrantTypes) {
        OAuthAdminService oAuthAdminService = new OAuthAdminService();
        List<String> allowedGrantTypes = Arrays.asList(oAuthAdminService.getAllowedGrantTypes());
        List<String> validGrantTypes = new ArrayList<>();

        for (String requestedGrant : requestedGrantTypes) {
            if (StringUtils.isBlank(requestedGrant)) {
                continue;
            }

            if (allowedGrantTypes.contains(requestedGrant)) {
                validGrantTypes.add(requestedGrant);
            }
        }

        return validGrantTypes;
    }

    /**
     * Convert the Application object to the ApplicationDTO object.
     * @param application Instance of an @see Application class.
     * @return Instance of @see ApplicationDTO
     */
    public static ApplicationDTO getApplicationDTOFromApplication(ExtendedApplication application) {

        if (application == null) {
            return null;
        }

        ApplicationDTO applicationDTO = new ApplicationDTO();
        applicationDTO.setClientId(application.getClientId());
        applicationDTO.setClientName(application.getClientName());
        applicationDTO.setClientSecret(application.getClientSecret());
        applicationDTO.setRedirectUris(application.getRedirectUris());
        applicationDTO.setGrantTypes(validateGrantTypes(application.getGrantTypes()));
        applicationDTO.setExtApplicationOwner(MultitenantUtils.
                getTenantAwareUsername(application.getApplicationOwner()));
        applicationDTO.setExtApplicationTokenLifetime(application.getApplicationAccessTokenLifeTime());
        applicationDTO.setExtUserTokenLifetime(application.getUserAccessTokenLifeTime());
        applicationDTO.setExtRefreshTokenLifetime(application.getRefreshTokenLifeTime());
        applicationDTO.setExtIdTokenLifetime(application.getIdTokenLifeTime());
        applicationDTO.setPkceMandatory(application.getPkceMandatory());
        applicationDTO.setPkceSupportPlain(application.getPkceSupportPlain());
        applicationDTO.setBypassClientCredentials(application.getBypassClientCredentials());
        applicationDTO.setTokenTypeExtension(application.getTokenType());
        applicationDTO.setApplicationScopes(application.getApplicationScopes());
        if (ExtendedDCRMUtils.isMultipleClientSecretsEnabled()) {
            applicationDTO.setExtClientSecretDescription(application.getSecretDescription());
            if (application.getSecretExpiryTime() != null) {
                applicationDTO.setClientSecretExpiresAt(String.valueOf(application.getSecretExpiryTime()));
            }
        }
        return applicationDTO;
    }

    /**
     * build the DCRMEndpointException
     * @param status status
     * @param code code
     * @param description description
     * @param isStatusOnly isStatusOnly
     * @return DCRMEndpointException
     */
    private static DCRMEndpointException buildDCRMEndpointException(Response.Status status,
                                                                    String code, String description,
                                                                    boolean isStatusOnly) {

        if (isStatusOnly) {
            return new DCRMEndpointException(status);
        } else {
            String error = DCRMConstants.ErrorCodes.INVALID_CLIENT_METADATA;
            if (code.equals(DCRMConstants.ErrorMessages.BAD_REQUEST_INVALID_REDIRECT_URI.toString())) {
                error = DCRMConstants.ErrorCodes.INVALID_REDIRECT_URI;
            }

            ErrorDTO errorDTO = new ErrorDTO();
            errorDTO.setMessage(error);
            errorDTO.setDescription(description);
            return new DCRMEndpointException(status, errorDTO);
        }
    }

    /**
     * build the DCRMEndpointException
     * @param status status
     * @param code code
     * @param message message
     * @param description description
     * @return DCRMEndpointException
     */
    private static DCRMEndpointException buildDCRMEndpointException(Response.Status status, String code,
                                                                    String message, String description) {

        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(code);
        errorDTO.setMessage(message);
        errorDTO.setDescription(description);
        return new DCRMEndpointException(status, errorDTO);
    }


    /**
     * Create a deep copy of the input Service Provider.
     *
     * @param serviceProvider Service Provider.
     * @return Clone of serviceProvider.
     */
    public static ServiceProvider cloneServiceProvider(ServiceProvider serviceProvider) {

        Gson gson = new Gson();
        ServiceProvider clonedServiceProvider = gson.fromJson(gson.toJson(serviceProvider), ServiceProvider.class);
        return clonedServiceProvider;
    }
    /**
     * Converts the input data transfer object into a ClientSecretCreationRequest for creating a new client secret.
     *
     * @param clientId the client identifier for which the secret is being created
     * @param clientSecretGenerationRequestDTO the DTO containing optional description and expiry information
     * @return a fully populated {@link ClientSecretGenerationRequest} object ready for client secret creation
     */
    public static ClientSecretGenerationRequest getClientSecretCreationRequest(
            String clientId, ClientSecretGenerationRequestDTO clientSecretGenerationRequestDTO) {

        ClientSecretGenerationRequest request = new ClientSecretGenerationRequest();
        request.setClientId(clientId);
        if (clientSecretGenerationRequestDTO != null) {
            request.setDescription(clientSecretGenerationRequestDTO.getDescription());
            if (clientSecretGenerationRequestDTO.getExpiresIn() != null) {
                request.setExpiresAt(calculateExpiresAt(clientSecretGenerationRequestDTO.getExpiresIn()));
            }
        }
        return request;
    }

    /**
     * Converts a {@link ClientSecret} entity into a {@link ClientSecretResponseDTO}
     *
     * @param clientSecret the client secret entity to convert; may be null
     * @return a {@link ClientSecretResponseDTO} populated from the input entity, or null if input is null
     */
    public static ClientSecretResponseDTO getClientSecretDTOFromClientSecret(ClientSecret clientSecret) {
        if (clientSecret == null) {
            return null;
        }

        ClientSecretResponseDTO clientSecretDTO = new ClientSecretResponseDTO();
        clientSecretDTO.setId(clientSecret.getSecretId());
        clientSecretDTO.setDescription(clientSecret.getDescription());
        clientSecretDTO.setClientSecret(clientSecret.getClientSecret());
        // Convert milliseconds to seconds for API response
        clientSecretDTO.setClientSecretExpiresAt(clientSecret.getExpiryTime() / 1000);
        return clientSecretDTO;
    }

    /**
     * Converts a list of {@link ClientSecret} entities into a {@link ClientSecretListDTO} containing
     * {@link ClientSecretResponseDTO} objects.
     *
     * @param clientSecrets the list of client secret entities; may be null or empty
     * @return a {@link ClientSecretListDTO} containing the converted client secrets and their count
     */
    public static ClientSecretListDTO getClientSecretListDTOFromClientSecretList(List<ClientSecret> clientSecrets) {

        ClientSecretListDTO clientSecretListDTO = new ClientSecretListDTO();

        List<ClientSecretResponseDTO> clientSecretList = new ArrayList<>();
        if (clientSecrets != null) {
            for (ClientSecret clientSecret : clientSecrets) {
                clientSecretList.add(getClientSecretDTOFromClientSecret(clientSecret));
            }
        }

        clientSecretListDTO.setList(clientSecretList);
        clientSecretListDTO.setCount(clientSecretList.size());
        return clientSecretListDTO;
    }

    /**
     * Calculate the expiry time in milliseconds since the epoch based on the current time and the
     * given expiresIn value.
     *
     * @param expiresIn The number of seconds until expiration.
     * @return The calculated expiry time in milliseconds since the epoch.
     */
    private static long calculateExpiresAt(int expiresIn) {
        return Instant.now().plusSeconds(expiresIn).toEpochMilli();
    }

    /**
     * Enum representing error scenarios related to multiple client secrets errors.
     */
    public enum MultipleClientSecretsError {

        DISABLED("60100",
                "The requested operation is not supported",
                "Multiple client secret support is disabled by server configuration."),

        ENABLED("60101",
                "The requested operation is not supported",
                "Multiple client secret support is enabled by server configuration. Use the client secret " +
                        "creation API (POST /dcr/register/{clientId}/secrets) to generate new client secrets.");

        private final String code;
        private final String message;
        private final String description;

        MultipleClientSecretsError(String code, String message, String description) {
            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {
            return code;
        }
        public String getMessage() {
            return message;
        }
        public String getDescription() {
            return description;
        }
    }

    /**
     * Check whether multiple client secrets feature is enabled.
     *
     * @return true if multiple client secrets feature is enabled, false otherwise.
     */
    public static boolean isMultipleClientSecretsEnabled() {
        return IdentityUtil.getProperty(MULTIPLE_CLIENT_SECRETS_ENABLED) != null &&
                Boolean.parseBoolean(IdentityUtil.getProperty(MULTIPLE_CLIENT_SECRETS_ENABLED));
    }
}
