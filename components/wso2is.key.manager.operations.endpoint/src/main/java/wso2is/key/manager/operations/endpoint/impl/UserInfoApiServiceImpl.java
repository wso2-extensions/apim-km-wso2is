package wso2is.key.manager.operations.endpoint.impl;

import org.apache.cxf.jaxrs.ext.MessageContext;
import wso2is.key.manager.operations.endpoint.*;
import wso2is.key.manager.operations.endpoint.dto.*;
import wso2is.key.manager.operations.endpoint.dto.ClaimRequestDTO;
import wso2is.key.manager.operations.endpoint.dto.ErrorDTO;

import javax.ws.rs.core.Response;


public class UserInfoApiServiceImpl implements UserInfoApiService {

    public Response userInfoClaimsGeneratePost(ClaimRequestDTO properties, MessageContext messageContext) {
        // remove errorObject and add implementation code!
        ErrorDTO errorObject = new ErrorDTO();
        Response.Status status  = Response.Status.NOT_IMPLEMENTED;
        errorObject.setCode(Integer.toString(status.getStatusCode()));
        errorObject.setMessage(status.toString());
        errorObject.setDescription("The requested resource has not been implemented");
        return Response.status(status).entity(errorObject).build();
    }

    public Response userInfoClaimsGet(String username, String domain, String dialect, MessageContext messageContext) {
        // remove errorObject and add implementation code!
        ErrorDTO errorObject = new ErrorDTO();
        Response.Status status  = Response.Status.NOT_IMPLEMENTED;
        errorObject.setCode(Integer.toString(status.getStatusCode()));
        errorObject.setMessage(status.toString());
        errorObject.setDescription("The requested resource has not been implemented");
        return Response.status(status).entity(errorObject).build();
    }
}
