package org.wso2.is.key.manager.operations.endpoint;

import org.wso2.is.key.manager.operations.endpoint.dto.ApplicationDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretCreationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.RegistrationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.UpdateRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.DcrApiService;
import org.wso2.is.key.manager.operations.endpoint.impl.DcrApiServiceImpl;

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
@Path("/dcr")

@Api(description = "the dcr API")
@Consumes({ "application/json" })
@Produces({ "application/json" })


public class DcrApi  {

  @Context MessageContext securityContext;

DcrApiService delegate = new DcrApiServiceImpl();


    @POST
    @Path("/register/{clientId}/change-owner")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Change Application Owner", notes = "This operation is used to change the owner of an Application. ", response = ApplicationDTO.class, tags={ "OAuth2 DCR",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Created", response = ApplicationDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 409, message = "Conflict", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response changeApplicationOwner( @NotNull @ApiParam(value = "",required=true)  @QueryParam("applicationOwner") String applicationOwner, @ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("clientId") String clientId){
        return delegate.changeApplicationOwner(applicationOwner, clientId, securityContext);
    }

    @POST
    @Path("/register/{clientId}/secrets")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Create new OAuth client secret", notes = "This operation is used to create a new OAuth client secret ", response = ClientSecretDTO.class, tags={ "OAuth2 DCR",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Secret successfully created", response = ClientSecretDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 409, message = "Conflict", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response createClientSecret(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("clientId") String clientId, @ApiParam(value = "Request payload containing details for creating a new client secret" ,required=true) ClientSecretCreationRequestDTO clientSecretCreateRequest){
        return delegate.createClientSecret(clientId, clientSecretCreateRequest, securityContext);
    }

    @DELETE
    @Path("/register/{client_id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Delete OAuth2 application ", notes = "This API is used to delete an OAuth2 application by client_id. ", response = Void.class, tags={ "OAuth2 DCR",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 204, message = "Successfully deleted", response = Void.class),
        @ApiResponse(code = 404, message = "Not Found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response deleteApplication(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("client_id") String clientId){
        return delegate.deleteApplication(clientId, securityContext);
    }

    @DELETE
    @Path("/register/{clientId}/secrets/{secretId}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Delete an OAuth client secret", notes = "This operation is used to delete an OAuth client secret ", response = Void.class, tags={ "OAuth2 DCR",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 204, message = "Secret revoked successfully", response = Void.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = ErrorDTO.class),
        @ApiResponse(code = 403, message = "Forbidden", response = ErrorDTO.class),
        @ApiResponse(code = 404, message = "Not Found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response deleteClientSecret(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("clientId") String clientId, @ApiParam(value = "Unique identifier of the secret to delete",required=true) @PathParam("secretId") String secretId){
        return delegate.deleteClientSecret(clientId, secretId, securityContext);
    }

    @GET
    @Path("/register/{client_id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Get OAuth2 application information ", notes = "This API is used to get/retrieve an OAuth2 application by client_id. ", response = ApplicationDTO.class, tags={ "OAuth2 DCR",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Successfully Retrieved", response = ApplicationDTO.class),
        @ApiResponse(code = 404, message = "Not Found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response getApplication(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("client_id") String clientId){
        return delegate.getApplication(clientId, securityContext);
    }

    @POST
    @Path("/register/{clientId}/regenerate-consumer-secret")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "update the oauth secret key", notes = "This operation is used to update the oauth secret key ", response = ApplicationDTO.class, tags={ "OAuth2 DCR",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Created", response = ApplicationDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 409, message = "Conflict", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response regenerateConsumerSecret(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("clientId") String clientId){
        return delegate.regenerateConsumerSecret(clientId, securityContext);
    }

    @POST
    @Path("/register")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Registers an OAuth2 application ", notes = "If you want to register an OAuth2 application with a specified client_id and secret, check the sample request given below. ", response = ApplicationDTO.class, tags={ "OAuth2 DCR",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Created", response = ApplicationDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 409, message = "Conflict", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response registerApplication(@ApiParam(value = "Application information to register." ,required=true) RegistrationRequestDTO registrationRequest){
        return delegate.registerApplication(registrationRequest, securityContext);
    }

    @PUT
    @Path("/register/{client_id}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Updates an OAuth2 application ", notes = "This API is used to update an OAuth2 application. ", response = ApplicationDTO.class, tags={ "OAuth2 DCR" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Successfully updated", response = ApplicationDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 409, message = "Conflict", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response updateApplication(@ApiParam(value = "Application information to update." ,required=true) UpdateRequestDTO updateRequest, @ApiParam(value = "Unique identifier for the OAuth2 client application.",required=true) @PathParam("client_id") String clientId){
        return delegate.updateApplication(updateRequest, clientId, securityContext);
    }
}
