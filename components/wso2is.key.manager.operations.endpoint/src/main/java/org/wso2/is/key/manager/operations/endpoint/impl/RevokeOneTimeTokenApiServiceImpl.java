package org.wso2.is.key.manager.operations.endpoint.impl;

import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.is.key.manager.operations.endpoint.RevokeOneTimeTokenApiService;
import org.wso2.is.key.manager.operations.endpoint.dto.RevokeTokenDTO;
import org.wso2.is.key.manager.operations.endpoint.userinfo.util.UserInfoUtil;
import javax.ws.rs.core.Response;

/**
 * Service Implementation for One Time Token Revocation
 */
public class RevokeOneTimeTokenApiServiceImpl implements RevokeOneTimeTokenApiService {
    public Response revokeOneTimeTokenPost(RevokeTokenDTO token, MessageContext messageContext) {
        String tokenId = token.getToken();
        if (tokenId == null || tokenId.length() == 0) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(UserInfoUtil.getError(Response.Status.BAD_REQUEST.toString(), "Bad request",
                            "Token Id is empty"))
                    .build();
        }
        String clientId = token.getClientId();
        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setAuthenticated(true);
        oAuthClientAuthnContext.setClientId(clientId);
        OAuthRevocationRequestDTO revocationRequest =
                OAuth2Util.buildOAuthRevocationRequest(oAuthClientAuthnContext, tokenId);
        OAuthRevocationResponseDTO oauthRevokeResponse = getOauth2Service().revokeTokenByOAuthClient(revocationRequest);
        if (oauthRevokeResponse.getErrorMsg() == null) {
            return Response.status(Response.Status.OK)
                    .entity(UserInfoUtil.getError(Response.Status.OK.toString(), "Success",
                            "Successfully revoked token " + tokenId))
                    .build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(UserInfoUtil.getError(Response.Status.BAD_REQUEST.toString(), "Bad request",
                            oauthRevokeResponse.getErrorMsg()))
                    .build();
        }

    }
    private static OAuth2Service getOauth2Service() {
        return (OAuth2Service) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2Service.class, null);
    }
}
