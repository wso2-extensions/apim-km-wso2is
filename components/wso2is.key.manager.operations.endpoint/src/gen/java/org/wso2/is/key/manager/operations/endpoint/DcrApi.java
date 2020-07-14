package org.wso2.is.key.manager.operations.endpoint;

import org.wso2.is.key.manager.operations.endpoint.dto.ApplicationDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.RegistrationRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.UpdateRequestDTO;
import org.wso2.is.key.manager.operations.endpoint.impl.DcrApiServiceImpl;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import io.swagger.annotations.*;

import org.apache.cxf.jaxrs.ext.MessageContext;

@Path("/dcr")

@Api(description = "the dcr API")
@Consumes({ "application/json" })
@Produces({ "application/json" })


public class DcrApi  {

  @Context MessageContext securityContext;

DcrApiService delegate = new DcrApiServiceImpl();


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
