package wso2is.key.manager.userinfo.endpoint.impl;

import wso2is.key.manager.userinfo.endpoint.*;
import wso2is.key.manager.userinfo.endpoint.dto.*;


import wso2is.key.manager.userinfo.endpoint.dto.ErrorDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ClaimListDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ClaimRequestDTO;

import java.util.List;

import java.io.InputStream;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;

import javax.ws.rs.core.Response;

public class ClaimsApiServiceImpl extends ClaimsApiService {
    @Override
    public Response claimsUsernameGenerateClaimsPost(String username,ClaimRequestDTO properties){
        // do some magic!
        return Response.ok().entity(new ApiResponseMessage(ApiResponseMessage.OK, "magic!")).build();
    }
    @Override
    public Response claimsUsernameGet(String username,String domain,String dialect){
        // do some magic!
        return Response.ok().entity(new ApiResponseMessage(ApiResponseMessage.OK, "magic!")).build();
    }
}
