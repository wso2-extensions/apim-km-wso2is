package wso2is.key.manager.userinfo.endpoint;

import wso2is.key.manager.userinfo.endpoint.dto.ClaimListDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ClaimRequestDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ErrorDTO;
import wso2is.key.manager.userinfo.endpoint.ClaimsApiService;
import wso2is.key.manager.userinfo.endpoint.impl.ClaimsApiServiceImpl;

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
    public Response claimsGeneratePost(@ApiParam(value = "Additional parameters that can be used to generate claims." ,required=true) ClaimRequestDTO properties) {
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
    public Response claimsGet( @NotNull @ApiParam(value = "User name ",required=true)  @QueryParam("username") String username,  @ApiParam(value = "Domain of the user. ")  @QueryParam("domain") String domain,  @ApiParam(value = "Dialect URI for the claims. ")  @QueryParam("dialect") String dialect) {
        return delegate.claimsGet(username, domain, dialect, securityContext);
    }
}
