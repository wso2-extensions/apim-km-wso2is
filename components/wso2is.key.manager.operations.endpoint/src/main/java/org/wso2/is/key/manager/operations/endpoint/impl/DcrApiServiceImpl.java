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
package org.wso2.is.key.manager.operations.endpoint.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.is.key.manager.operations.endpoint.DcrApiService;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ClientSecret;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ClientSecretGenerationRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplication;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplicationRegistrationRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.service.DCRMService;
import org.wso2.is.key.manager.operations.endpoint.dcr.util.ExtendedDCRMUtils;
import org.wso2.is.key.manager.operations.endpoint.dto.ApplicationDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretGenerationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretListDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretResponseDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.RegistrationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.UpdateRequestDTO;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import javax.ws.rs.core.Response;

/**
 * Service Implementation for DCR API
 */
public class DcrApiServiceImpl implements DcrApiService {

    private static final Log LOG = LogFactory.getLog(DcrApiServiceImpl.class);

    private DCRMService service = new DCRMService();

    @Override
    public Response changeApplicationOwner(String applicationOwner, String clientId, MessageContext messageContext) {
        ApplicationDTO applicationDTO = null;
        try {
            clientId = new String(Base64.getUrlDecoder().decode(clientId), StandardCharsets.UTF_8);
            ExtendedApplication application = service.updateApplicationOwner(applicationOwner, clientId);
            applicationDTO = ExtendedDCRMUtils.getApplicationDTOFromApplication(application);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.OK).entity(applicationDTO).build();
    }

    /**
     * Create a new client secret for the OAuth application identified by the given client ID.
     *
     * @param clientId                  The client ID of the OAuth application.
     * @param clientSecretCreateRequest The request object containing details for the new client secret.
     * @param messageContext            The message context.
     * @return A Response object containing the created client secret details or an error response.
     */
    @Override
    public Response generateClientSecret(String clientId, ClientSecretGenerationRequestDTO clientSecretCreateRequest,
                                       MessageContext messageContext) {
        if (!ExtendedDCRMUtils.isMultipleClientSecretsEnabled()) {
            ErrorDTO errorDTO = ExtendedDCRMUtils.getError(
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getCode(),
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getMessage(),
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getDescription()
            );
            return Response.status(Response.Status.FORBIDDEN).entity(errorDTO).build();
        }
        clientId = new String(Base64.getUrlDecoder().decode(clientId), StandardCharsets.UTF_8);
        ClientSecretResponseDTO clientSecretDTO = null;
        try {
            ClientSecretGenerationRequest request = ExtendedDCRMUtils.
                    getClientSecretCreationRequest(clientId, clientSecretCreateRequest);
            ClientSecret clientSecret = service.createClientSecret(request);
            clientSecretDTO = ExtendedDCRMUtils.getClientSecretDTOFromClientSecret(clientSecret);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while creating new client secret " + clientSecretCreateRequest, e);
            }
            ExtendedDCRMUtils.handleErrorResponse(e, LOG);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.CREATED).entity(clientSecretDTO).build();
    }

    @Override
    public Response deleteApplication(String clientId, MessageContext messageContext) {
        try {
            clientId = new String(Base64.getUrlDecoder().decode(clientId), StandardCharsets.UTF_8);
            service.deleteApplication(clientId);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while deleting  application with client key:" + clientId, e);
            }
            ExtendedDCRMUtils.handleErrorResponse(e, LOG);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.NO_CONTENT).build();
    }

    /**
     * Delete a specific client secret associated with the OAuth application identified by the given client ID.
     *
     * @param clientId      The client ID of the OAuth application.
     * @param secretId      The ID of the client secret to be deleted.
     * @param messageContext The message context.
     * @return A Response object indicating the result of the delete operation.
     */
    @Override
    public Response deleteClientSecret(String clientId, String secretId, MessageContext messageContext) {
        if (!ExtendedDCRMUtils.isMultipleClientSecretsEnabled()) {
            ErrorDTO errorDTO = ExtendedDCRMUtils.getError(
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getCode(),
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getMessage(),
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getDescription()
            );
            return Response.status(Response.Status.FORBIDDEN).entity(errorDTO).build();
        }
        try {
            clientId = new String(Base64.getUrlDecoder().decode(clientId), StandardCharsets.UTF_8);
            secretId = new String(Base64.getUrlDecoder().decode(secretId), StandardCharsets.UTF_8);
            service.deleteClientSecret(secretId);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while deleting  application with client key:" + clientId, e);
            }
            ExtendedDCRMUtils.handleErrorResponse(e, LOG);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.NO_CONTENT).build();
    }

    @Override
    public Response getApplication(String clientId, MessageContext messageContext) {
        ApplicationDTO applicationDTO = null;
        try {
            clientId = new String(Base64.getUrlDecoder().decode(clientId), StandardCharsets.UTF_8);
            ExtendedApplication application = service.getApplication(clientId);
            applicationDTO = ExtendedDCRMUtils.getApplicationDTOFromApplication(application);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while retrieving  application with client key:" + clientId, e);
            }
            ExtendedDCRMUtils.handleErrorResponse(e, LOG);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.OK).entity(applicationDTO).build();
    }

    @Override
    public Response getClientSecret(String clientId, String secretId, MessageContext messageContext) {
        return Response.status(Response.Status.METHOD_NOT_ALLOWED).entity("Not Implemented").build();
    }

    /**
     * Retrieve all client secrets associated with the OAuth application identified by the given client ID.
     *
     * @param clientId      The client ID of the OAuth application.
     * @param messageContext The message context.
     * @return A Response object containing a list of client secrets or an error response.
     */
    @Override
    public Response getClientSecrets(String clientId, MessageContext messageContext) {
        if (!ExtendedDCRMUtils.isMultipleClientSecretsEnabled()) {
            ErrorDTO errorDTO = ExtendedDCRMUtils.getError(
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getCode(),
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getMessage(),
                    ExtendedDCRMUtils.MultipleClientSecretsError.DISABLED.getDescription()
            );
            return Response.status(Response.Status.FORBIDDEN).entity(errorDTO).build();
        }
        clientId = new String(Base64.getUrlDecoder().decode(clientId), StandardCharsets.UTF_8);
        ClientSecretListDTO clientSecretListDTO = null;
        try {
            List<ClientSecret> clientSecretList = service.getClientSecrets(clientId);
            clientSecretListDTO = ExtendedDCRMUtils.getClientSecretListDTOFromClientSecretList(clientSecretList);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error client secrets of client " + clientId, e);
            }
            ExtendedDCRMUtils.handleErrorResponse(e, LOG);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.OK).entity(clientSecretListDTO).build();
    }

    @Override
    public Response regenerateConsumerSecret(String clientId, MessageContext messageContext) {
        if (ExtendedDCRMUtils.isMultipleClientSecretsEnabled()) {
            ErrorDTO errorDTO = ExtendedDCRMUtils.getError(
                    ExtendedDCRMUtils.MultipleClientSecretsError.ENABLED.getCode(),
                    ExtendedDCRMUtils.MultipleClientSecretsError.ENABLED.getMessage(),
                    ExtendedDCRMUtils.MultipleClientSecretsError.ENABLED.getDescription()
            );
            return Response.status(Response.Status.FORBIDDEN).entity(errorDTO).build();
        }
        ApplicationDTO applicationDTO = null;
        try {
            clientId = new String(Base64.getUrlDecoder().decode(clientId), StandardCharsets.UTF_8);
            ExtendedApplication application = service.getNewApplicationConsumerSecret(clientId);
            applicationDTO = ExtendedDCRMUtils.getApplicationDTOFromApplication(application);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.OK).entity(applicationDTO).build();
    }

    @Override
    public Response registerApplication(RegistrationRequestDTO registrationRequest, MessageContext messageContext) {
        ApplicationDTO applicationDTO = null;

        try {
            ExtendedApplicationRegistrationRequest request = ExtendedDCRMUtils.
                    getApplicationRegistrationRequest(registrationRequest);
            ExtendedApplication application = service.registerApplication(request);
            applicationDTO = ExtendedDCRMUtils.getApplicationDTOFromApplication(application);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while registering application \n" + registrationRequest.toString(), e);
            }
            ExtendedDCRMUtils.handleErrorResponse(e, LOG);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.CREATED).entity(applicationDTO).build();
    }

    @Override
    public Response updateApplication(UpdateRequestDTO updateRequest, String clientId, MessageContext messageContext) {
        ApplicationDTO applicationDTO = null;
        try {
            clientId = new String(Base64.getUrlDecoder().decode(clientId), StandardCharsets.UTF_8);
            ExtendedApplication application = service.updateApplication(ExtendedDCRMUtils.getApplicationUpdateRequest(
                    updateRequest), clientId);

            applicationDTO = ExtendedDCRMUtils.getApplicationDTOFromApplication(application);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while updating application \n" + updateRequest.toString(), e);
            }
            ExtendedDCRMUtils.handleErrorResponse(e, LOG);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.OK).entity(applicationDTO).build();
    }
}
