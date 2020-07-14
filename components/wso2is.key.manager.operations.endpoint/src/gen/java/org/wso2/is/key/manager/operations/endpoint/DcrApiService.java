package org.wso2.is.key.manager.operations.endpoint;

import org.apache.cxf.jaxrs.ext.MessageContext;

import org.wso2.is.key.manager.operations.endpoint.dto.RegistrationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.UpdateRequestDTO;

import javax.ws.rs.core.Response;

public interface DcrApiService {
      public Response deleteApplication(String clientId, MessageContext messageContext) ;
      public Response getApplication(String clientId, MessageContext messageContext) ;
      public Response registerApplication(RegistrationRequestDTO registrationRequest, MessageContext messageContext) ;
      public Response updateApplication(UpdateRequestDTO updateRequest, String clientId, MessageContext messageContext) ;
}
