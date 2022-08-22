/*
 *  Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.is.key.manager.operations.endpoint.impl;

import org.apache.cxf.jaxrs.ext.MessageContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.junit4.PowerMockRunner;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.is.key.manager.operations.endpoint.dto.ErrorDTO;
import org.wso2.is.key.manager.operations.endpoint.dto.RevokeTokenInfoDTO;
import org.wso2.is.key.manager.operations.endpoint.userinfo.util.UserInfoUtil;

import javax.ws.rs.core.Response;

/**
 * This class tests the RevokeOneTimeTokenApiServiceImpl class for the One Time Token Revocation
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({RevokeOneTimeTokenApiServiceImpl.class, UserInfoUtil.class, OAuth2Util.
        class, PrivilegedCarbonContext.class})
@SuppressStaticInitializationFor("org.wso2.carbon.identity.oauth2.util.OAuth2Util")
public class RevokeOneTimeTokenApiServiceImplTest {

    private RevokeOneTimeTokenApiServiceImpl revokeService;
    private MessageContext messageContext;
    private RevokeTokenInfoDTO revokeTokenInfoDTO;
    private OAuthRevocationResponseDTO oAuthRevocationResponseDTO;

    @Before
    public void init() throws Exception {

        System.setProperty("carbon.home", "1234");

        revokeService = PowerMockito.spy(new RevokeOneTimeTokenApiServiceImpl());

        PowerMockito.mockStatic(UserInfoUtil.class);
        PowerMockito.mockStatic(OAuth2Util.class);
        PowerMockito.mockStatic(PrivilegedCarbonContext.class);

        messageContext = Mockito.mock(MessageContext.class);
        revokeTokenInfoDTO = Mockito.mock(RevokeTokenInfoDTO.class);
        OAuthClientAuthnContext oAuthClientAuthnContext = Mockito.mock(OAuthClientAuthnContext.class);
        OAuthRevocationRequestDTO oAuthRevocationRequestDTO = Mockito.mock(OAuthRevocationRequestDTO.class);
        PrivilegedCarbonContext privilegedCarbonContext = Mockito.mock(PrivilegedCarbonContext.class);
        OAuth2Service oAuth2Service = Mockito.mock(OAuth2Service.class);
        oAuthRevocationResponseDTO = Mockito.mock(OAuthRevocationResponseDTO.class);
        ErrorDTO errorDto = Mockito.mock(ErrorDTO.class);

        PowerMockito.when(UserInfoUtil.getError(Mockito.anyString(), Mockito.anyString(),
                Mockito.anyString())).thenReturn(errorDto);

        Mockito.when(revokeTokenInfoDTO.getToken()).thenReturn("testToken");
        Mockito.when(revokeTokenInfoDTO.getConsumerKey()).thenReturn("testConsumerKey");

        PowerMockito.whenNew(OAuthClientAuthnContext.class).withAnyArguments().thenReturn(oAuthClientAuthnContext);
        Mockito.doNothing().when(oAuthClientAuthnContext).setAuthenticated(Mockito.anyBoolean());
        Mockito.doNothing().when(oAuthClientAuthnContext).setClientId(Mockito.anyString());
        PowerMockito.when(OAuth2Util.buildOAuthRevocationRequest(Mockito.any(OAuthClientAuthnContext.class),
                Mockito.anyString())).thenReturn(oAuthRevocationRequestDTO);
        PowerMockito.when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);
        PowerMockito.when(privilegedCarbonContext.getOSGiService(OAuth2Service.class, null)).
                thenReturn(oAuth2Service);
        Mockito.when(oAuth2Service.revokeTokenByOAuthClient(Mockito.any(OAuthRevocationRequestDTO.class))).
                thenReturn(oAuthRevocationResponseDTO);

        PowerMockito.when(revokeService, "getMaskedToken", Mockito.anyString()).
                thenReturn("maskedToken");
    }

    /**
     * The happy path of the method with all attributes available
     */
    @Test
    public void testRevokeOneTimeTokenPost() {

        Mockito.when(oAuthRevocationResponseDTO.getErrorMsg()).thenReturn(null);
        Response response = revokeService.revokeOneTimeTokenPost(revokeTokenInfoDTO, messageContext);
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
    }

    /**
     * Testing when the token revocation is failed in the oAuth2Service.revokeTokenByOAuthClient function
     */
    @Test
    public void testRevokeOneTimeTokenPostWithFailedRevocation() {

        Mockito.when(oAuthRevocationResponseDTO.getErrorMsg()).thenReturn("some error message");
        Response response = revokeService.revokeOneTimeTokenPost(revokeTokenInfoDTO, messageContext);
        Assert.assertEquals(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), response.getStatus());
    }

    /**
     * Testing when the token is null
     */
    @Test
    public void testRevokeOneTimeTokenPostWithNullToken() {

        Mockito.when(revokeTokenInfoDTO.getToken()).thenReturn("");
        Response response = revokeService.revokeOneTimeTokenPost(revokeTokenInfoDTO, messageContext);
        Assert.assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }

    /**
     * Testing when the consumer key is null
     */
    @Test
    public void testRevokeOneTimeTokenPostWithNullConsumerKey() {

        Mockito.when(revokeTokenInfoDTO.getConsumerKey()).thenReturn("");
        Response response = revokeService.revokeOneTimeTokenPost(revokeTokenInfoDTO, messageContext);
        Assert.assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
    }
}
