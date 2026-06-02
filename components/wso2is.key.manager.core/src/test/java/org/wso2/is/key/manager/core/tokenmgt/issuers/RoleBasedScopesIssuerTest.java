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
package org.wso2.is.key.manager.core.tokenmgt.issuers;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.wso2.carbon.apimgt.impl.issuers.SystemScopesIssuer;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;
import org.wso2.is.key.manager.core.internal.ServiceReferenceHolder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit tests covering the scope-filtering refactor in {@link RoleBasedScopesIssuer}.
 *
 * The behavior under test is the product REST API scope (apim:, apim_analytics:, service_catalog:) pass-through,
 * which is now gated solely by the presence of a registered {@code SystemScopesIssuer} scope validator
 * (via {@code isSystemScopeIssuerAvailable()}) instead of the {@code restrict.unassigned.scopes} and
 * {@code restrict.apim.restapi.scopes} system-property flags. The related system-property scenarios
 * ({@code restrict.unassigned.scopes} in {@code getAuthorizedScopes} and {@code preservedCaseSensitive}) are
 * covered as well.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthServerConfiguration.class})
public class RoleBasedScopesIssuerTest {

    private static final String PRESERVED_CASE_SENSITIVE_VARIABLE = "preservedCaseSensitive";
    private static final String PRODUCT_SCOPE_1 = "apim:api_view";
    private static final String PRODUCT_SCOPE_2 = "service_catalog:view";
    private static final String PRODUCT_SCOPE_3 = "apim_analytics:view";
    private static final String APP_SCOPE = "scope_internal";
    private static final String DEFAULT_SCOPE = "default";

    private RoleBasedScopesIssuer scopesIssuer;
    private List<String> allowedScopes;

    @Before
    public void init() throws Exception {

        // Mock the OAuthServerConfiguration singleton so constructing the issuer does not load real server config.
        PowerMockito.mockStatic(OAuthServerConfiguration.class);
        OAuthServerConfiguration oAuthServerConfiguration = Mockito.mock(OAuthServerConfiguration.class);
        PowerMockito.when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        allowedScopes = new ArrayList<>();
        Mockito.when(oAuthServerConfiguration.getAllowedScopes()).thenReturn(allowedScopes);

        scopesIssuer = PowerMockito.spy(new RoleBasedScopesIssuer());

        // Start every test from a clean shared-state baseline.
        ServiceReferenceHolder.getInstance().getScopeValidators().clear();
        ServiceReferenceHolder.setRestrictUnassignedScopes(false);
        ServiceReferenceHolder.setRestrictApimRestApiScopes(false);
        System.clearProperty(PRESERVED_CASE_SENSITIVE_VARIABLE);
    }

    @After
    public void cleanup() {

        ServiceReferenceHolder.getInstance().getScopeValidators().clear();
        ServiceReferenceHolder.setRestrictUnassignedScopes(false);
        ServiceReferenceHolder.setRestrictApimRestApiScopes(false);
        System.clearProperty(PRESERVED_CASE_SENSITIVE_VARIABLE);
    }

    private void registerSystemScopesIssuer() {

        ServiceReferenceHolder.getInstance().addScopeValidator(new SystemScopesIssuer());
    }

    // ------------------------------------------------------------------------------------------------
    // getScopes(OAuthAuthzReqMessageContext)
    // ------------------------------------------------------------------------------------------------

    private OAuthAuthzReqMessageContext mockAuthzContext(String[] approvedScopes) {

        OAuthAuthzReqMessageContext context = Mockito.mock(OAuthAuthzReqMessageContext.class);
        OAuth2AuthorizeReqDTO authorizeReqDTO = Mockito.mock(OAuth2AuthorizeReqDTO.class);
        AuthenticatedUser user = Mockito.mock(AuthenticatedUser.class);
        Mockito.when(context.getApprovedScope()).thenReturn(approvedScopes);
        Mockito.when(context.getAuthorizationReqDTO()).thenReturn(authorizeReqDTO);
        Mockito.when(authorizeReqDTO.getConsumerKey()).thenReturn("client-1");
        Mockito.when(authorizeReqDTO.getUser()).thenReturn(user);
        return context;
    }

    @Test
    public void testAuthzProductScopesPassThroughWhenSystemIssuerAvailable() throws Exception {

        registerSystemScopesIssuer();
        // When the pass-through works, requestedScopes is emptied and the method returns before getAppScopes is
        // reached; this stub only takes effect if the (regressed) code falls through, yielding a clean assertion
        // failure instead of a NoClassDefFoundError from real infrastructure.
        PowerMockito.doReturn(null).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthAuthzReqMessageContext context = mockAuthzContext(new String[]{PRODUCT_SCOPE_1, PRODUCT_SCOPE_2});

        List<String> result = scopesIssuer.getScopes(context);

        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_1
                + " should pass through to SystemScopesIssuer when one is registered; got " + result,
                result.contains(PRODUCT_SCOPE_1));
        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_2
                + " should pass through to SystemScopesIssuer when one is registered; got " + result,
                result.contains(PRODUCT_SCOPE_2));
        Assert.assertEquals("Only the two requested product scopes should be returned; got " + result,
                2, result.size());
    }

    @Test
    public void testAuthzProductScopesDroppedWhenSystemIssuerNotAvailable() {

        OAuthAuthzReqMessageContext context = mockAuthzContext(new String[]{PRODUCT_SCOPE_1, PRODUCT_SCOPE_2});

        List<String> result = scopesIssuer.getScopes(context);

        // No SystemScopesIssuer: product scopes are dropped and requestedScopes becomes empty -> default scope.
        Assert.assertEquals("Without a SystemScopesIssuer, product scopes are dropped leaving only the default "
                + "scope; got " + result, 1, result.size());
        Assert.assertTrue("Result should fall back to the default scope " + DEFAULT_SCOPE + "; got " + result,
                result.contains(DEFAULT_SCOPE));
    }

    @Test
    public void testAuthzMixedScopesWithSystemIssuer() throws Exception {

        registerSystemScopesIssuer();
        PowerMockito.doReturn(new HashMap<String, String>()).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthAuthzReqMessageContext context = mockAuthzContext(new String[]{PRODUCT_SCOPE_1, APP_SCOPE});

        List<String> result = scopesIssuer.getScopes(context);

        // Product scope passes through, app scope passes through the empty-app-scopes branch.
        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_1 + " should pass through with a SystemScopesIssuer; got "
                + result, result.contains(PRODUCT_SCOPE_1));
        Assert.assertTrue("App scope " + APP_SCOPE + " should be retained; got " + result,
                result.contains(APP_SCOPE));
        Assert.assertEquals("Both the product scope and the app scope should be returned; got " + result,
                2, result.size());
    }

    @Test
    public void testAuthzMixedScopesWithoutSystemIssuer() throws Exception {

        PowerMockito.doReturn(new HashMap<String, String>()).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthAuthzReqMessageContext context = mockAuthzContext(new String[]{PRODUCT_SCOPE_1, APP_SCOPE});

        List<String> result = scopesIssuer.getScopes(context);

        // Product scope dropped, only the app scope remains.
        Assert.assertFalse("Product scope " + PRODUCT_SCOPE_1
                + " should be dropped without a SystemScopesIssuer; got " + result,
                result.contains(PRODUCT_SCOPE_1));
        Assert.assertTrue("App scope " + APP_SCOPE + " should be retained; got " + result,
                result.contains(APP_SCOPE));
        Assert.assertEquals("Only the app scope should remain; got " + result, 1, result.size());
    }

    @Test
    public void testAuthzNullApprovedScope() throws Exception {

        OAuthAuthzReqMessageContext context = Mockito.mock(OAuthAuthzReqMessageContext.class);
        OAuth2AuthorizeReqDTO authorizeReqDTO = Mockito.mock(OAuth2AuthorizeReqDTO.class);
        Mockito.when(context.getApprovedScope()).thenReturn(null);
        Mockito.when(context.getAuthorizationReqDTO()).thenReturn(authorizeReqDTO);
        Mockito.when(authorizeReqDTO.getConsumerKey()).thenReturn("client-1");
        Mockito.when(authorizeReqDTO.getUser()).thenReturn(Mockito.mock(AuthenticatedUser.class));
        PowerMockito.doReturn(null).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.any());

        List<String> result = scopesIssuer.getScopes(context);

        Assert.assertTrue("A null approved scope should yield no authorized scopes; got " + result,
                result.isEmpty());
    }

    // ------------------------------------------------------------------------------------------------
    // Regression: restrict.* flags no longer gate product REST API scope pass-through (option 1)
    // ------------------------------------------------------------------------------------------------

    @Test
    public void testRestrictFlagsDoNotGateProductScopesWhenSystemIssuerAvailable() throws Exception {

        // Both restrict flags ON used to suppress product scope pass-through; now only the SystemScopesIssuer matters.
        ServiceReferenceHolder.setRestrictUnassignedScopes(true);
        ServiceReferenceHolder.setRestrictApimRestApiScopes(true);
        registerSystemScopesIssuer();
        PowerMockito.doReturn(null).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthAuthzReqMessageContext context = mockAuthzContext(new String[]{PRODUCT_SCOPE_1, PRODUCT_SCOPE_3});

        List<String> result = scopesIssuer.getScopes(context);

        Assert.assertTrue("restrict.* flags must not gate pass-through; product scope " + PRODUCT_SCOPE_1
                + " should pass through when a SystemScopesIssuer is registered; got " + result,
                result.contains(PRODUCT_SCOPE_1));
        Assert.assertTrue("restrict.* flags must not gate pass-through; product scope " + PRODUCT_SCOPE_3
                + " should pass through when a SystemScopesIssuer is registered; got " + result,
                result.contains(PRODUCT_SCOPE_3));
        Assert.assertEquals("Only the two requested product scopes should be returned; got " + result,
                2, result.size());
    }

    @Test
    public void testRestrictFlagsDoNotForceProductScopesWhenSystemIssuerNotAvailable() {

        // Both restrict flags OFF used to force product scope pass-through; now the absence of the SystemScopesIssuer
        // drops them regardless of the flags.
        ServiceReferenceHolder.setRestrictUnassignedScopes(false);
        ServiceReferenceHolder.setRestrictApimRestApiScopes(false);
        OAuthAuthzReqMessageContext context = mockAuthzContext(new String[]{PRODUCT_SCOPE_1, PRODUCT_SCOPE_3});

        List<String> result = scopesIssuer.getScopes(context);

        Assert.assertFalse("Without a SystemScopesIssuer, product scope " + PRODUCT_SCOPE_1
                + " should be dropped regardless of the restrict.* flags; got " + result,
                result.contains(PRODUCT_SCOPE_1));
        Assert.assertFalse("Without a SystemScopesIssuer, product scope " + PRODUCT_SCOPE_3
                + " should be dropped regardless of the restrict.* flags; got " + result,
                result.contains(PRODUCT_SCOPE_3));
        Assert.assertEquals("Only the default scope should remain; got " + result, 1, result.size());
        Assert.assertTrue("Result should fall back to the default scope " + DEFAULT_SCOPE + "; got " + result,
                result.contains(DEFAULT_SCOPE));
    }

    // ------------------------------------------------------------------------------------------------
    // getScopes(OAuthCallback)
    // ------------------------------------------------------------------------------------------------

    private OAuthCallback mockCallback(String[] requestedScopes) {

        OAuthCallback callback = Mockito.mock(OAuthCallback.class);
        Mockito.when(callback.getRequestedScope()).thenReturn(requestedScopes);
        Mockito.when(callback.getClient()).thenReturn("client-1");
        Mockito.when(callback.getResourceOwner()).thenReturn(Mockito.mock(AuthenticatedUser.class));
        return callback;
    }

    @Test
    public void testCallbackProductScopesPassThroughWhenSystemIssuerAvailable() throws Exception {

        registerSystemScopesIssuer();
        PowerMockito.doReturn(null).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthCallback callback = mockCallback(new String[]{PRODUCT_SCOPE_1, PRODUCT_SCOPE_2});

        List<String> result = scopesIssuer.getScopes(callback);

        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_1
                + " should pass through (OAuthCallback) when a SystemScopesIssuer is registered; got " + result,
                result.contains(PRODUCT_SCOPE_1));
        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_2
                + " should pass through (OAuthCallback) when a SystemScopesIssuer is registered; got " + result,
                result.contains(PRODUCT_SCOPE_2));
        Assert.assertEquals("Only the two requested product scopes should be returned; got " + result,
                2, result.size());
    }

    @Test
    public void testCallbackProductScopesDroppedWhenSystemIssuerNotAvailable() {

        OAuthCallback callback = mockCallback(new String[]{PRODUCT_SCOPE_1, PRODUCT_SCOPE_2});

        List<String> result = scopesIssuer.getScopes(callback);

        Assert.assertEquals("Without a SystemScopesIssuer (OAuthCallback), product scopes are dropped leaving only "
                + "the default scope; got " + result, 1, result.size());
        Assert.assertTrue("Result should fall back to the default scope " + DEFAULT_SCOPE + "; got " + result,
                result.contains(DEFAULT_SCOPE));
    }

    @Test
    public void testCallbackMixedScopesWithSystemIssuer() throws Exception {

        registerSystemScopesIssuer();
        PowerMockito.doReturn(new HashMap<String, String>()).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthCallback callback = mockCallback(new String[]{PRODUCT_SCOPE_2, APP_SCOPE});

        List<String> result = scopesIssuer.getScopes(callback);

        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_2
                + " should pass through (OAuthCallback) with a SystemScopesIssuer; got " + result,
                result.contains(PRODUCT_SCOPE_2));
        Assert.assertTrue("App scope " + APP_SCOPE + " should be retained; got " + result,
                result.contains(APP_SCOPE));
        Assert.assertEquals("Both the product scope and the app scope should be returned; got " + result,
                2, result.size());
    }

    @Test
    public void testCallbackMixedScopesWithoutSystemIssuer() throws Exception {

        PowerMockito.doReturn(new HashMap<String, String>()).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthCallback callback = mockCallback(new String[]{PRODUCT_SCOPE_2, APP_SCOPE});

        List<String> result = scopesIssuer.getScopes(callback);

        Assert.assertFalse("Product scope " + PRODUCT_SCOPE_2
                + " should be dropped (OAuthCallback) without a SystemScopesIssuer; got " + result,
                result.contains(PRODUCT_SCOPE_2));
        Assert.assertTrue("App scope " + APP_SCOPE + " should be retained; got " + result,
                result.contains(APP_SCOPE));
        Assert.assertEquals("Only the app scope should remain; got " + result, 1, result.size());
    }

    // ------------------------------------------------------------------------------------------------
    // getScopes(OAuthTokenReqMessageContext)
    // ------------------------------------------------------------------------------------------------

    private OAuthTokenReqMessageContext mockTokenContext(String[] requestedScopes, String grantType) {

        OAuthTokenReqMessageContext context = Mockito.mock(OAuthTokenReqMessageContext.class);
        OAuth2AccessTokenReqDTO tokenReqDTO = Mockito.mock(OAuth2AccessTokenReqDTO.class);
        Mockito.when(context.getScope()).thenReturn(requestedScopes);
        Mockito.when(context.getOauth2AccessTokenReqDTO()).thenReturn(tokenReqDTO);
        Mockito.when(context.getAuthorizedUser()).thenReturn(Mockito.mock(AuthenticatedUser.class));
        Mockito.when(tokenReqDTO.getClientId()).thenReturn("client-1");
        Mockito.when(tokenReqDTO.getGrantType()).thenReturn(grantType);
        return context;
    }

    @Test
    public void testTokenProductScopesPassThroughWhenSystemIssuerAvailable() throws Exception {

        registerSystemScopesIssuer();
        PowerMockito.doReturn(null).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthTokenReqMessageContext context =
                mockTokenContext(new String[]{PRODUCT_SCOPE_1, PRODUCT_SCOPE_2}, "authorization_code");

        List<String> result = scopesIssuer.getScopes(context);

        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_1
                + " should pass through (token flow) when a SystemScopesIssuer is registered; got " + result,
                result.contains(PRODUCT_SCOPE_1));
        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_2
                + " should pass through (token flow) when a SystemScopesIssuer is registered; got " + result,
                result.contains(PRODUCT_SCOPE_2));
        Assert.assertEquals("Only the two requested product scopes should be returned; got " + result,
                2, result.size());
    }

    @Test
    public void testTokenProductScopesDroppedWhenSystemIssuerNotAvailable() {

        OAuthTokenReqMessageContext context =
                mockTokenContext(new String[]{PRODUCT_SCOPE_1, PRODUCT_SCOPE_2}, "authorization_code");

        List<String> result = scopesIssuer.getScopes(context);

        Assert.assertEquals("Without a SystemScopesIssuer (token flow), product scopes are dropped leaving only "
                + "the default scope; got " + result, 1, result.size());
        Assert.assertTrue("Result should fall back to the default scope " + DEFAULT_SCOPE + "; got " + result,
                result.contains(DEFAULT_SCOPE));
    }

    @Test
    public void testTokenMixedScopesWithSystemIssuer() throws Exception {

        registerSystemScopesIssuer();
        PowerMockito.doReturn(new HashMap<String, String>()).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthTokenReqMessageContext context =
                mockTokenContext(new String[]{PRODUCT_SCOPE_1, APP_SCOPE}, "authorization_code");

        List<String> result = scopesIssuer.getScopes(context);

        Assert.assertTrue("Product scope " + PRODUCT_SCOPE_1
                + " should pass through (token flow) with a SystemScopesIssuer; got " + result,
                result.contains(PRODUCT_SCOPE_1));
        Assert.assertTrue("App scope " + APP_SCOPE + " should be retained; got " + result,
                result.contains(APP_SCOPE));
        Assert.assertEquals("Both the product scope and the app scope should be returned; got " + result,
                2, result.size());
    }

    @Test
    public void testTokenMixedScopesWithoutSystemIssuer() throws Exception {

        PowerMockito.doReturn(new HashMap<String, String>()).when(scopesIssuer)
                .getAppScopes(Mockito.anyString(), Mockito.any(AuthenticatedUser.class), Mockito.anyList());
        OAuthTokenReqMessageContext context =
                mockTokenContext(new String[]{PRODUCT_SCOPE_1, APP_SCOPE}, "authorization_code");

        List<String> result = scopesIssuer.getScopes(context);

        Assert.assertFalse("Product scope " + PRODUCT_SCOPE_1
                + " should be dropped (token flow) without a SystemScopesIssuer; got " + result,
                result.contains(PRODUCT_SCOPE_1));
        Assert.assertTrue("App scope " + APP_SCOPE + " should be retained; got " + result,
                result.contains(APP_SCOPE));
        Assert.assertEquals("Only the app scope should remain; got " + result, 1, result.size());
    }

    // ------------------------------------------------------------------------------------------------
    // isSystemScopeIssuerAvailable()
    // ------------------------------------------------------------------------------------------------

    @Test
    public void testIsSystemScopeIssuerAvailableTrue() throws Exception {

        registerSystemScopesIssuer();
        boolean available = Whitebox.invokeMethod(scopesIssuer, "isSystemScopeIssuerAvailable");
        Assert.assertTrue("isSystemScopeIssuerAvailable() should return true when a SystemScopesIssuer is registered",
                available);
    }

    @Test
    public void testIsSystemScopeIssuerAvailableFalseWhenEmpty() throws Exception {

        boolean available = Whitebox.invokeMethod(scopesIssuer, "isSystemScopeIssuerAvailable");
        Assert.assertFalse("isSystemScopeIssuerAvailable() should return false when no validators are registered",
                available);
    }

    @Test
    public void testIsSystemScopeIssuerAvailableFalseWithOtherValidator() throws Exception {

        // A different validator (e.g. RoleBasedScopesIssuer itself) must not be mistaken for the SystemScopesIssuer.
        ServiceReferenceHolder.getInstance().addScopeValidator(Mockito.mock(ScopeValidator.class));
        ServiceReferenceHolder.getInstance().addScopeValidator(new RoleBasedScopesIssuer());

        boolean available = Whitebox.invokeMethod(scopesIssuer, "isSystemScopeIssuerAvailable");
        Assert.assertFalse("isSystemScopeIssuerAvailable() should return false when only non-SystemScopesIssuer "
                + "validators are registered", available);
    }

    // ------------------------------------------------------------------------------------------------
    // getAuthorizedScopes() - related system-property scenarios (options 2 and 3)
    // ------------------------------------------------------------------------------------------------

    @Test
    public void testRestrictUnassignedScopesFiltersUnassignedScopes() throws Exception {

        // option 2: restrict.unassigned.scopes still filters scopes that are neither app scopes nor whitelisted.
        ServiceReferenceHolder.setRestrictUnassignedScopes(true);
        allowedScopes.add("whitelisted_scope");

        Map<String, String> appScopes = new HashMap<>();
        appScopes.put("app_scope", "");
        String[] userRoles = new String[]{"admin"};
        List<String> requestedScopes = new ArrayList<>(
                Arrays.asList("app_scope", "unassigned_scope", "whitelisted_scope"));

        List<String> result = Whitebox.invokeMethod(scopesIssuer, "getAuthorizedScopes",
                userRoles, requestedScopes, appScopes);

        Assert.assertTrue("App scope should be authorized; got " + result, result.contains("app_scope"));
        Assert.assertTrue("Whitelisted scope should be authorized; got " + result,
                result.contains("whitelisted_scope"));
        Assert.assertFalse("Unassigned scope must be filtered when restrict.unassigned.scopes is on; got " + result,
                result.contains("unassigned_scope"));
    }

    @Test
    public void testRestrictUnassignedScopesDisabledAllowsAllScopes() throws Exception {

        ServiceReferenceHolder.setRestrictUnassignedScopes(false);

        Map<String, String> appScopes = new HashMap<>();
        appScopes.put("app_scope", "");
        String[] userRoles = new String[]{"admin"};
        List<String> requestedScopes = new ArrayList<>(Arrays.asList("app_scope", "unassigned_scope"));

        List<String> result = Whitebox.invokeMethod(scopesIssuer, "getAuthorizedScopes",
                userRoles, requestedScopes, appScopes);

        Assert.assertTrue("App scope should be authorized; got " + result, result.contains("app_scope"));
        Assert.assertTrue("Unassigned scope should be allowed when restrict.unassigned.scopes is off; got " + result,
                result.contains("unassigned_scope"));
    }

    @Test
    public void testPreservedCaseSensitiveDisabledMatchesRolesCaseInsensitively() throws Exception {

        // option 3: with preservedCaseSensitive off, role matching is case-insensitive.
        System.clearProperty(PRESERVED_CASE_SENSITIVE_VARIABLE);

        Map<String, String> appScopes = new HashMap<>();
        appScopes.put("scope1", "Admin");
        String[] userRoles = new String[]{"admin"};
        List<String> requestedScopes = new ArrayList<>(Arrays.asList("scope1"));

        List<String> result = Whitebox.invokeMethod(scopesIssuer, "getAuthorizedScopes",
                userRoles, requestedScopes, appScopes);

        Assert.assertTrue("With preservedCaseSensitive off, role 'admin' should match scope role 'Admin'; got "
                + result, result.contains("scope1"));
    }

    @Test
    public void testPreservedCaseSensitiveEnabledMatchesRolesCaseSensitively() throws Exception {

        // option 3: with preservedCaseSensitive on, "admin" does not match the scope role "Admin" -> default scope.
        System.setProperty(PRESERVED_CASE_SENSITIVE_VARIABLE, "true");

        Map<String, String> appScopes = new HashMap<>();
        appScopes.put("scope1", "Admin");
        String[] userRoles = new String[]{"admin"};
        List<String> requestedScopes = new ArrayList<>(Arrays.asList("scope1"));

        List<String> result = Whitebox.invokeMethod(scopesIssuer, "getAuthorizedScopes",
                userRoles, requestedScopes, appScopes);

        Assert.assertFalse("With preservedCaseSensitive on, role 'admin' should not match scope role 'Admin'; got "
                + result, result.contains("scope1"));
        Assert.assertTrue("Result should fall back to the default scope " + DEFAULT_SCOPE + "; got " + result,
                result.contains(DEFAULT_SCOPE));
    }
}
