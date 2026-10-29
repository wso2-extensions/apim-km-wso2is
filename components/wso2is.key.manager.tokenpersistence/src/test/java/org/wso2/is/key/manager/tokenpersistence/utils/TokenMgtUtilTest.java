/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
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
package org.wso2.is.key.manager.tokenpersistence.utils;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

/**
 * This class tests the TokenMgtUtil class for resolving federated users from the user session store.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({UserSessionStore.class})
public class TokenMgtUtilTest {

    private static final String USER_ID = "4b4414e1-916b-4475-aaee-6b0751c29ff6";
    private static final String USER_NAME = "user1@example.com";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String IDP_NAME = "TestIdP";

    private UserSessionStore userSessionStore;

    @Before
    public void init() {

        userSessionStore = Mockito.mock(UserSessionStore.class);
        PowerMockito.mockStatic(UserSessionStore.class);
        PowerMockito.when(UserSessionStore.getInstance()).thenReturn(userSessionStore);
    }

    @Test
    public void testCreateFederatedAuthenticatedUserSkipsFederatedDomain() throws Exception {

        Mockito.when(userSessionStore.getUser(USER_ID)).thenReturn(createSessionUser("FEDERATED"));

        AuthenticatedUser authenticatedUser = TokenMgtUtil.createFederatedAuthenticatedUser(USER_ID);

        Assert.assertNull("Reserved FEDERATED marker should not be set as the user store domain",
                authenticatedUser.getUserStoreDomain());
        Assert.assertEquals(USER_NAME, authenticatedUser.getUserName());
        Assert.assertEquals(TENANT_DOMAIN, authenticatedUser.getTenantDomain());
        Assert.assertEquals(IDP_NAME, authenticatedUser.getFederatedIdPName());
        Assert.assertEquals(USER_ID, authenticatedUser.getUserId());
        Assert.assertTrue(authenticatedUser.isFederatedUser());
    }

    @Test
    public void testCreateFederatedAuthenticatedUserSkipsFederatedDomainWithIdPSuffix() throws Exception {

        Mockito.when(userSessionStore.getUser(USER_ID)).thenReturn(createSessionUser("FEDERATED:" + IDP_NAME));

        AuthenticatedUser authenticatedUser = TokenMgtUtil.createFederatedAuthenticatedUser(USER_ID);

        Assert.assertNull(authenticatedUser.getUserStoreDomain());
        Assert.assertEquals(USER_NAME, authenticatedUser.getUserName());
    }

    @Test
    public void testCreateFederatedAuthenticatedUserKeepsUserStoreDomain() throws Exception {

        Mockito.when(userSessionStore.getUser(USER_ID)).thenReturn(createSessionUser("PRIMARY"));

        AuthenticatedUser authenticatedUser = TokenMgtUtil.createFederatedAuthenticatedUser(USER_ID);

        Assert.assertEquals("PRIMARY", authenticatedUser.getUserStoreDomain());
        Assert.assertEquals(USER_NAME, authenticatedUser.getUserName());
        Assert.assertTrue(authenticatedUser.isFederatedUser());
    }

    @Test
    public void testCreateFederatedAuthenticatedUserDoesNotModifySessionUser() throws Exception {

        AuthenticatedUser sessionUser = createSessionUser("FEDERATED");
        Mockito.when(userSessionStore.getUser(USER_ID)).thenReturn(sessionUser);

        AuthenticatedUser authenticatedUser = TokenMgtUtil.createFederatedAuthenticatedUser(USER_ID);

        Assert.assertNotSame(sessionUser, authenticatedUser);
        Assert.assertEquals("FEDERATED", sessionUser.getUserStoreDomain());
    }

    @Test(expected = IdentityOAuth2Exception.class)
    public void testCreateFederatedAuthenticatedUserWhenUserNotFound() throws Exception {

        Mockito.when(userSessionStore.getUser(USER_ID)).thenReturn(null);

        TokenMgtUtil.createFederatedAuthenticatedUser(USER_ID);
    }

    @Test(expected = IdentityOAuth2Exception.class)
    public void testCreateFederatedAuthenticatedUserWhenSessionStoreFails() throws Exception {

        Mockito.when(userSessionStore.getUser(USER_ID)).thenThrow(new UserSessionException("error"));

        TokenMgtUtil.createFederatedAuthenticatedUser(USER_ID);
    }

    private AuthenticatedUser createSessionUser(String userStoreDomain) {

        AuthenticatedUser sessionUser = new AuthenticatedUser();
        sessionUser.setUserName(USER_NAME);
        sessionUser.setTenantDomain(TENANT_DOMAIN);
        sessionUser.setUserStoreDomain(userStoreDomain);
        sessionUser.setFederatedIdPName(IDP_NAME);
        return sessionUser;
    }
}
