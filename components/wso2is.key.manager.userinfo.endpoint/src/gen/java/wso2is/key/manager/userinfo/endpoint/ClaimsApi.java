package wso2is.key.manager.userinfo.endpoint;

import wso2is.key.manager.userinfo.endpoint.dto.*;
import wso2is.key.manager.userinfo.endpoint.ClaimsApiService;
import wso2is.key.manager.userinfo.endpoint.factories.ClaimsApiServiceFactory;

import io.swagger.annotations.ApiParam;

import wso2is.key.manager.userinfo.endpoint.dto.ErrorDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ClaimListDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ClaimRequestDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;

import javax.ws.rs.core.Response;
import javax.ws.rs.*;

@Path("/claims")
@Consumes({ "application/json" })
@Produces({ "application/json" })
@io.swagger.annotations.Api(value = "/claims", description = "the claims API")
public class ClaimsApi  {

   private final ClaimsApiService delegate = ClaimsApiServiceFactory.getClaimsApi();

    @POST
    @Path("/generate")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Register user\n", notes = "This API is used to get user claims.\n", response = ClaimListDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Claims returned."),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "User not found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response claimsGeneratePost(@ApiParam(value = "Additional parameters that can be used to generate claims." ,required=true ) ClaimRequestDTO properties)
    {
    return delegate.claimsGeneratePost(properties);
    }
    @GET
    
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @io.swagger.annotations.ApiOperation(value = "Register user\n", notes = "This API is used to get user claims.\n", response = ClaimListDTO.class)
    @io.swagger.annotations.ApiResponses(value = { 
        @io.swagger.annotations.ApiResponse(code = 200, message = "Claims returned."),
        
        @io.swagger.annotations.ApiResponse(code = 400, message = "Bad Request"),
        
        @io.swagger.annotations.ApiResponse(code = 404, message = "User not found"),
        
        @io.swagger.annotations.ApiResponse(code = 500, message = "Server Error") })

    public Response claimsGet(@ApiParam(value = "User name\n",required=true) @QueryParam("username")  String username,
    @ApiParam(value = "Domain of the user.\n") @QueryParam("domain")  String domain,
    @ApiParam(value = "Dialect URI for the claims.\n") @QueryParam("dialect")  String dialect)
    {
    return delegate.claimsGet(username,domain,dialect);
    }
}

