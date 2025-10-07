package org.wso2.is.key.manager.operations.endpoint;

import org.wso2.is.key.manager.operations.endpoint.dto.ApplicationDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretGenerationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretListDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ClientSecretResponseDTO;
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
    @ApiOperation(value = "Delete an OAuth2 client secret", notes = "This operation is used to delete an OAuth2 client secret ", response = Void.class, tags={ "OAuth2 Client Secrets",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 204, message = "Secret revoked successfully", response = Void.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = ErrorDTO.class),
        @ApiResponse(code = 404, message = "Not Found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response deleteClientSecret(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("clientId") String clientId, @ApiParam(value = "Unique identifier of the secret to delete",required=true) @PathParam("secretId") String secretId){
        return delegate.deleteClientSecret(clientId, secretId, securityContext);
    }

    @POST
    @Path("/register/{clientId}/generate-secret")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Generate new OAuth2 client secret", notes = "This operation is used to generate a new OAuth2 client secret ", response = ClientSecretResponseDTO.class, tags={ "OAuth2 Client Secrets",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 201, message = "Secret generated successfully", response = ClientSecretResponseDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = ErrorDTO.class),
        @ApiResponse(code = 409, message = "Conflict", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response generateClientSecret(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("clientId") String clientId, @ApiParam(value = "Request payload containing details for generating a new client secret" ,required=true) ClientSecretGenerationRequestDTO clientSecretCreateRequest){
        return delegate.generateClientSecret(clientId, clientSecretCreateRequest, securityContext);
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

    @GET
    @Path("/register/{clientId}/secrets/{secretId}")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Get a secret of an OAuth2 client", notes = "This operation is used to get a secret of an OAuth2 client ", response = ClientSecretResponseDTO.class, tags={ "OAuth2 Client Secrets",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Requested secret of the client is returned.", response = ClientSecretResponseDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = ErrorDTO.class),
        @ApiResponse(code = 404, message = "Secret not found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response getClientSecret(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("clientId") String clientId, @ApiParam(value = "Unique identifier of the secret to retrieve",required=true) @PathParam("secretId") String secretId){
        return delegate.getClientSecret(clientId, secretId, securityContext);
    }

    @GET
    @Path("/register/{clientId}/secrets")
    @Consumes({ "application/json" })
    @Produces({ "application/json" })
    @ApiOperation(value = "Get secrets of an OAuth2 client", notes = "This operation is used to get the secrets of an OAuth2 client ", response = ClientSecretListDTO.class, tags={ "OAuth2 Client Secrets",  })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "Secrets of the client is returned.", response = ClientSecretListDTO.class),
        @ApiResponse(code = 400, message = "Bad Request", response = ErrorDTO.class),
        @ApiResponse(code = 401, message = "Unauthorized", response = ErrorDTO.class),
        @ApiResponse(code = 404, message = "Client not found", response = ErrorDTO.class),
        @ApiResponse(code = 500, message = "Server Error", response = ErrorDTO.class) })
    public Response getClientSecrets(@ApiParam(value = "Unique identifier of the OAuth2 client application.",required=true) @PathParam("clientId") String clientId){
        return delegate.getClientSecrets(clientId, securityContext);
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
