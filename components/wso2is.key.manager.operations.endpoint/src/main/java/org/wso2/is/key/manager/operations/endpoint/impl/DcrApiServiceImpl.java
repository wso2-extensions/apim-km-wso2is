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
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplication;
import org.wso2.is.key.manager.operations.endpoint.dcr.bean.ExtendedApplicationRegistrationRequest;
import org.wso2.is.key.manager.operations.endpoint.dcr.service.DCRMService;
import org.wso2.is.key.manager.operations.endpoint.dcr.util.ExtendedDCRMUtils;
import org.wso2.is.key.manager.operations.endpoint.dto.ApplicationDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.RegistrationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.UpdateRequestDTO;

import java.util.Base64;
import javax.ws.rs.core.Response;

/**
 * Service Implementation for DCR API
 */
public class DcrApiServiceImpl implements DcrApiService {

    private static final Log LOG = LogFactory.getLog(DcrApiServiceImpl.class);
    private static final String encodeConsumerKey = "encodeConsumerKey";

    private DCRMService service = new DCRMService();

    @Override
    public Response changeApplicationOwner(String applicationOwner, String clientId, MessageContext messageContext) {
        ApplicationDTO applicationDTO = null;
        try {
            ExtendedApplication application = service.updateApplicationOwner(applicationOwner, clientId);
            applicationDTO = ExtendedDCRMUtils.getApplicationDTOFromApplication(application);
        } catch (Throwable throwable) {
            ExtendedDCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable,
                    true, LOG);
        }
        return Response.status(Response.Status.OK).entity(applicationDTO).build();
    }

    @Override
    public Response deleteApplication(String clientId, MessageContext messageContext) {
        try {
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

    @Override
    public Response getApplication(String clientId, MessageContext messageContext) {
        ApplicationDTO applicationDTO = null;
        try {
            String isConsumerKeyEncoded = System.getProperty(encodeConsumerKey, "false");
            if (isConsumerKeyEncoded.equalsIgnoreCase("true")) {
                clientId = new String(Base64.getDecoder().decode(clientId), "UTF-8");
            }
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
    public Response regenerateConsumerSecret(String clientId, MessageContext messageContext) {
        ApplicationDTO applicationDTO = null;
        try {
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
            ExtendedApplication application = service
                    .updateApplication(ExtendedDCRMUtils.getApplicationUpdateRequest(updateRequest), clientId);

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
