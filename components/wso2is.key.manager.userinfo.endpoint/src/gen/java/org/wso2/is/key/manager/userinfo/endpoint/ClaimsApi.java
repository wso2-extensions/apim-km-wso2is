package org.wso2.is.key.manager.userinfo.endpoint;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.is.key.manager.userinfo.endpoint.dto.ClaimListDTO;
import org.wso2.is.key.manager.userinfo.endpoint.dto.ClaimRequestDTO;
import org.wso2.is.key.manager.userinfo.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.userinfo.endpoint.impl.ClaimsApiServiceImpl;

import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
@Path("/claims")

@Api(description = "the claims API")
@Consumes({ "application/json" })
@Produces({ "application/json" })


public class ClaimsApi  {

  @Context MessageContext securityContext;

ClaimsApiService delegate = new ClaimsApiServiceImpl();


    @POST
    @Path("/generate")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Register user ", notes = "This API is used to get user claims. ", response = ClaimListDTO.class, tags={ "User Claims",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Claims returned.", response = ClaimListDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 404, message = "User not found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response claimsGeneratePost(@ApiParam(value = "Additional parameters that can be used to generate claims." ,required=true) ClaimRequestDTO properties){
        return delegate.claimsGeneratePost(properties, securityContext);
    }

    @GET
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Register user ", notes = "This API is used to get user claims. ", response = ClaimListDTO.class, tags={ "User Claims" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Claims returned.", response = ClaimListDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 404, message = "User not found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response claimsGet( @NotNull @ApiParam(value = "User name ",required=true)  @QueryParam("username") String username,  @ApiParam(value = "Domain of the user. ")  @QueryParam("domain") String domain,  @ApiParam(value = "Dialect URI for the claims. ")  @QueryParam("dialect") String dialect){
        return delegate.claimsGet(username, domain, dialect, securityContext);
    }
}
