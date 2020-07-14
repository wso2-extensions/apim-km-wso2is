package org.wso2.is.key.manager.operations.endpoint;

import org.wso2.is.key.manager.operations.endpoint.dto.ClaimListDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClaimRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.operations.endpoint.UserInfoApiService;
import org.wso2.is.key.manager.operations.endpoint.impl.UserInfoApiServiceImpl;

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
@Path("/user-info")

@Api(description = "the user-info API")
@Consumes({ "application/json" })
@Produces({ "application/json" })


public class UserInfoApi  {

  @Context MessageContext securityContext;

UserInfoApiService delegate = new UserInfoApiServiceImpl();


    @POST
    @Path("/claims/generate")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Register user ", notes = "This API is used to get user claims. ", response = ClaimListDTO.class, tags={ "User Claims",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Claims returned.", response = ClaimListDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 404, message = "User not found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response userInfoClaimsGeneratePost(@ApiParam(value = "Additional parameters that can be used to generate claims." ,required=true) ClaimRequestDTO properties){
        return delegate.userInfoClaimsGeneratePost(properties, securityContext);
    }

    @GET
    @Path("/claims")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Register user ", notes = "This API is used to get user claims. ", response = ClaimListDTO.class, tags={ "User Claims" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Claims returned.", response = ClaimListDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 404, message = "User not found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response userInfoClaimsGet( @NotNull @ApiParam(value = "User name ",required=true)  @QueryParam("username") String username,  @ApiParam(value = "Domain of the user. ")  @QueryParam("domain") String domain,  @ApiParam(value = "Dialect URI for the claims. ")  @QueryParam("dialect") String dialect){
        return delegate.userInfoClaimsGet(username, domain, dialect, securityContext);
    }
}
