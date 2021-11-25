package org.wso2.is.key.manager.operations.endpoint;

import org.wso2.is.key.manager.operations.endpoint.*;
import org.wso2.is.key.manager.operations.endpoint.dto.*;

import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;


import org.wso2.is.key.manager.operations.endpoint.dto.ApplicationDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.RegistrationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.UpdateRequestDTO;

import java.util.List;

import java.io.InputStream;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;


public interface DcrApiService {
      public Response changeApplicationOwner(String applicationOwner, String clientId, MessageContext messageContext) ;
      public Response deleteApplication(String clientId, MessageContext messageContext) ;
      public Response getApplication(String clientId, Boolean encoded, MessageContext messageContext) ;
      public Response regenerateConsumerSecret(String clientId, MessageContext messageContext) ;
      public Response registerApplication(RegistrationRequestDTO registrationRequest, MessageContext messageContext) ;
      public Response updateApplication(UpdateRequestDTO updateRequest, String clientId, MessageContext messageContext) ;
}
