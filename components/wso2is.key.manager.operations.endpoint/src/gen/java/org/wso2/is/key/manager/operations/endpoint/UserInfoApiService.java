package org.wso2.is.key.manager.operations.endpoint;

import org.apache.cxf.jaxrs.ext.MessageContext;

import org.wso2.is.key.manager.operations.endpoint.dto.ClaimRequestDTO;

import javax.ws.rs.core.Response;

public interface UserInfoApiService {
      public Response userInfoClaimsGeneratePost(ClaimRequestDTO properties, MessageContext messageContext) ;
      public Response userInfoClaimsGet(String username, String domain, String dialect, MessageContext messageContext) ;
}
