package org.wso2.is.key.manager.operations.endpoint;

import org.wso2.is.key.manager.operations.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.RevokeTokenDTO;
import org.wso2.is.key.manager.operations.endpoint.RevokeOneTimeTokenApiService;
import org.wso2.is.key.manager.operations.endpoint.impl.RevokeOneTimeTokenApiServiceImpl;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import io.swagger.annotations.*;
import java.io.InputStream;

import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import java.util.Map;
import java.util.List;
import javax.validation.constraints.*;
@Path("/revoke-one-time-token")

@Api(description = "the revoke-one-time-token API")
@Consumes({ "application/json" })
@Produces({ "application/json" })


public class RevokeOneTimeTokenApi  {

  @Context MessageContext securityContext;

RevokeOneTimeTokenApiService delegate = new RevokeOneTimeTokenApiServiceImpl();


    @POST
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Revoking One Time Token ", notes = "Revoking the single usage token with the token id given in the body ", response = Void.class, tags={  })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Successfully Revoked", response = Void.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response revokeOneTimeTokenPost(@ApiParam(value = "Unique identifier of the OTT." ,required=true) RevokeTokenDTO token){
        return delegate.revokeOneTimeTokenPost(token, securityContext);
    }
}
