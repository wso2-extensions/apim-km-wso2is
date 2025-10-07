package org.wso2.is.key.manager.operations.endpoint;

import org.wso2.is.key.manager.operations.endpoint.*;
import org.wso2.is.key.manager.operations.endpoint.dto.*;

import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;


import org.wso2.is.key.manager.operations.endpoint.dto.ApplicationDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretGenerationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretListDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretResponseDTO;
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
      public Response deleteClientSecret(String clientId, String secretId, MessageContext messageContext) ;
      public Response generateClientSecret(String clientId, ClientSecretGenerationRequestDTO clientSecretCreateRequest, MessageContext messageContext) ;
      public Response getApplication(String clientId, MessageContext messageContext) ;
      public Response getClientSecret(String clientId, String secretId, MessageContext messageContext) ;
      public Response getClientSecrets(String clientId, MessageContext messageContext) ;
      public Response regenerateConsumerSecret(String clientId, MessageContext messageContext) ;
      public Response registerApplication(RegistrationRequestDTO registrationRequest, MessageContext messageContext) ;
      public Response updateApplication(UpdateRequestDTO updateRequest, String clientId, MessageContext messageContext) ;
}
