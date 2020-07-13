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
package wso2is.key.manager.operations.endpoint.dcr.util;

import org.apache.commons.logging.Log;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.util.DCRMUtils;
import wso2is.key.manager.operations.endpoint.dcr.bean.ExtendedApplication;
import wso2is.key.manager.operations.endpoint.dcr.bean.ExtendedApplicationRegistrationRequest;
import wso2is.key.manager.operations.endpoint.dcr.bean.ExtendedApplicationUpdateRequest;
import wso2is.key.manager.operations.endpoint.dcr.exception.DCRMEndpointException;
import wso2is.key.manager.operations.endpoint.dcr.service.ExtendedDCRMService;
import wso2is.key.manager.operations.endpoint.dto.ApplicationDTO;
import wso2is.key.manager.operations.endpoint.dto.ErrorDTO;
import wso2is.key.manager.operations.endpoint.dto.RegistrationRequestDTO;
import wso2is.key.manager.operations.endpoint.dto.UpdateRequestDTO;


import javax.ws.rs.core.Response;

/**
 * Util class used for OAuth DCRM.
 */
public class ExtendedDCRMUtils extends  DCRMUtils {

    private static final String CONFLICT_STATUS = "CONFLICT_";
    private static final String BAD_REQUEST_STATUS = "BAD_REQUEST_";
    private static final String NOT_FOUND_STATUS = "NOT_FOUND_";
    private static final String FORBIDDEN_STATUS = "FORBIDDEN_";

    private static ExtendedDCRMService oAuth2DCRMService;

    public static void setOAuth2DCRMService(ExtendedDCRMService oAuth2DCRMService) {

        ExtendedDCRMUtils.oAuth2DCRMService = oAuth2DCRMService;
    }

    public static ExtendedDCRMService getOAuth2DCRMService() {

        return oAuth2DCRMService;
    }

    public static ExtendedApplicationRegistrationRequest getApplicationRegistrationRequest(
            RegistrationRequestDTO registrationRequestDTO) {

        ExtendedApplicationRegistrationRequest appRegistrationRequest = new ExtendedApplicationRegistrationRequest();
        appRegistrationRequest.setClientName(registrationRequestDTO.getClientName());
        appRegistrationRequest.setRedirectUris(registrationRequestDTO.getRedirectUris());
        appRegistrationRequest.setGrantTypes(registrationRequestDTO.getGrantTypes());
        appRegistrationRequest.setTokenType(registrationRequestDTO.getTokenType());
        appRegistrationRequest.setApplicationOwner(registrationRequestDTO.getApplicationOwner());
        appRegistrationRequest.setConsumerKey(registrationRequestDTO.getClientId());
        appRegistrationRequest.setConsumerSecret(registrationRequestDTO.getClientSecret());
        appRegistrationRequest.setSpTemplateName(registrationRequestDTO.getSpTemplateName());
        appRegistrationRequest.setBackchannelLogoutUri(registrationRequestDTO.getBackchannelLogoutUri());
        return appRegistrationRequest;

    }

    public static ExtendedApplicationUpdateRequest getApplicationUpdateRequest(UpdateRequestDTO updateRequestDTO) {

        ExtendedApplicationUpdateRequest applicationUpdateRequest = new ExtendedApplicationUpdateRequest();
        applicationUpdateRequest.setClientName(updateRequestDTO.getClientName());
        applicationUpdateRequest.setRedirectUris(updateRequestDTO.getRedirectUris());
        applicationUpdateRequest.setGrantTypes(updateRequestDTO.getGrantTypes());
        applicationUpdateRequest.setTokenType(updateRequestDTO.getTokenType());
        applicationUpdateRequest.setBackchannelLogoutUri(updateRequestDTO.getBackchannelLogoutUri());
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
     * @throws DCRMEndpointException
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
        applicationDTO.setGrantTypes(application.getGrantTypes());

        return applicationDTO;
    }

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

}
