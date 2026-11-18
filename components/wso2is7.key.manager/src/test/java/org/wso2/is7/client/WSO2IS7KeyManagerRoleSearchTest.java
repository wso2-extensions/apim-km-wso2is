/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.is7.client;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.is7.client.model.WSO2IS7APIResourceManagementClient;
import org.wso2.is7.client.model.WSO2IS7PatchRoleOperationInfo;
import org.wso2.is7.client.model.WSO2IS7RoleInfo;
import org.wso2.is7.client.model.WSO2IS7SCIMRolesClient;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests that WSO2IS7KeyManager pages through the WSO2 IS7 role search results.
 */
public class WSO2IS7KeyManagerRoleSearchTest {

    private static final String SCOPE = "test_scope";
    private static final int TOTAL_ROLES = 114;

    private WSO2IS7KeyManager keyManager;
    private WSO2IS7SCIMRolesClient rolesClient;

    @BeforeClass
    public static void setUpLogging() {
        // Keep the fallback pax-logging logger at INFO, as debug logging fails outside OSGi.
        System.setProperty("org.ops4j.pax.logging.DefaultServiceLog.level", "INFO");
    }

    @Before
    public void setUp() throws Exception {
        // A mock that calls real methods avoids the field initializers, which need a running server.
        keyManager = mock(WSO2IS7KeyManager.class, CALLS_REAL_METHODS);
        rolesClient = mock(WSO2IS7SCIMRolesClient.class);
        setField("wso2IS7SCIMRolesClient", rolesClient);
    }

    @Test
    public void testSearchRolesReadsAllPages() throws Exception {
        when(rolesClient.searchRoles(any(JsonObject.class))).thenAnswer(
                invocation -> pagedResponse(invocation.getArgument(0), TOTAL_ROLES, true));

        JsonArray roles = searchRoles(null);

        assertEquals(TOTAL_ROLES, roles.size());
        ArgumentCaptor<JsonObject> payloads = ArgumentCaptor.forClass(JsonObject.class);
        verify(rolesClient, times(2)).searchRoles(payloads.capture());
        assertEquals(1, payloads.getAllValues().get(0).get("startIndex").getAsInt());
        assertEquals(101, payloads.getAllValues().get(1).get("startIndex").getAsInt());
        assertEquals(100, payloads.getAllValues().get(1).get("count").getAsInt());
    }

    @Test
    public void testSearchRolesWithoutResourcesReturnsEmptyArray() throws Exception {
        JsonObject response = new JsonObject();
        response.addProperty("totalResults", 0);
        when(rolesClient.searchRoles(any(JsonObject.class))).thenReturn(response);

        JsonArray roles = searchRoles(null);

        assertEquals(0, roles.size());
    }

    @Test
    public void testSearchRolesWithoutTotalResultsStopsOnShortPage() throws Exception {
        when(rolesClient.searchRoles(any(JsonObject.class))).thenAnswer(
                invocation -> pagedResponse(invocation.getArgument(0), TOTAL_ROLES, false));

        JsonArray roles = searchRoles(null);

        assertEquals(TOTAL_ROLES, roles.size());
        verify(rolesClient, times(2)).searchRoles(any(JsonObject.class));
    }

    @Test
    public void testSearchRolesStopsOnEmptyPageWhenTotalResultsIsOverstated() throws Exception {
        when(rolesClient.searchRoles(any(JsonObject.class))).thenAnswer(invocation -> {
            JsonObject response = pagedResponse(invocation.getArgument(0), TOTAL_ROLES, true);
            response.addProperty("totalResults", 500);
            return response;
        });

        JsonArray roles = searchRoles(null);

        assertEquals(TOTAL_ROLES, roles.size());
        verify(rolesClient, times(3)).searchRoles(any(JsonObject.class));
    }

    @Test
    public void testFilteredSearchReturnsSingleRole() throws Exception {
        when(rolesClient.searchRoles(any(JsonObject.class))).thenAnswer(
                invocation -> pagedResponse(invocation.getArgument(0), TOTAL_ROLES, true));

        JsonArray roles = searchRoles("displayName eq testrole005");

        assertEquals(1, roles.size());
        assertEquals("testrole005", roles.get(0).getAsJsonObject().get("displayName").getAsString());
        verify(rolesClient, times(1)).searchRoles(any(JsonObject.class));
    }

    @Test
    public void testUpdateScopeRemovesBindingOfRoleBeyondFirstPage() throws Exception {
        setField("enableRoleCreation", true);
        WSO2IS7APIResourceManagementClient apiResourceClient = mock(WSO2IS7APIResourceManagementClient.class);
        JsonObject apiResources = new JsonObject();
        apiResources.add("apiResources", new JsonArray());
        when(apiResourceClient.getAPIResources(any())).thenReturn(apiResources);
        setField("wso2IS7APIResourceManagementClient", apiResourceClient);
        when(rolesClient.searchRoles(any(JsonObject.class))).thenAnswer(
                invocation -> pagedResponse(invocation.getArgument(0), TOTAL_ROLES, true));
        WSO2IS7RoleInfo oldRole = new WSO2IS7RoleInfo();
        oldRole.setId("id-testrole005");
        oldRole.setPermissions(Collections.singletonList(Collections.singletonMap("value", SCOPE)));
        when(rolesClient.getRole("id-testrole005")).thenReturn(oldRole);

        Scope scope = new Scope();
        scope.setKey(SCOPE);
        scope.setName(SCOPE);
        scope.setRoles("Internal/testrole110");
        keyManager.updateScope(scope);

        ArgumentCaptor<WSO2IS7PatchRoleOperationInfo> patch =
                ArgumentCaptor.forClass(WSO2IS7PatchRoleOperationInfo.class);
        verify(rolesClient).patchRole(eq("id-testrole005"), patch.capture());
        assertTrue(patch.getValue().getOperations().get(0).getValue().getPermissions().isEmpty());
        verify(rolesClient, never()).patchRole(eq("id-testrole110"), any());
    }

    @Test
    public void testGetScopeByNameIncludesRoleBeyondFirstPage() throws Exception {
        useScopeResource();

        Scope scope = keyManager.getScopeByName(SCOPE);

        assertEquals("Internal/testrole110,Internal/testrole005", scope.getRoles());
        verify(rolesClient, times(2)).searchRoles(any(JsonObject.class));
    }

    @Test
    public void testGetAllScopesIncludesRoleBeyondFirstPage() throws Exception {
        useScopeResource();

        Map<String, Scope> scopes = keyManager.getAllScopes();

        assertEquals(1, scopes.size());
        assertEquals("testrole110,testrole005", scopes.get(SCOPE).getRoles());
        verify(rolesClient, times(2)).searchRoles(any(JsonObject.class));
    }

    @Test
    public void testUpdateResourceScopesRemovesBindingOfRoleBeyondFirstPage() throws Exception {
        useScopeResource();
        setField("enableRoleCreation", true);
        stubRole("testrole005", SCOPE);
        stubRole("testrole110", SCOPE);

        keyManager.updateResourceScopes(null, Collections.singleton(SCOPE),
                Collections.singleton(localScope(SCOPE, "Internal/testrole110")),
                Collections.emptySet(), Collections.emptySet());

        ArgumentCaptor<WSO2IS7PatchRoleOperationInfo> patch =
                ArgumentCaptor.forClass(WSO2IS7PatchRoleOperationInfo.class);
        verify(rolesClient).patchRole(eq("id-testrole005"), patch.capture());
        assertTrue(patch.getValue().getOperations().get(0).getValue().getPermissions().isEmpty());
        verify(rolesClient, never()).patchRole(eq("id-testrole110"), any());
    }

    @Test
    public void testUpdateResourceScopesKeepsRequestedRoleBeyondFirstPage() throws Exception {
        useScopeResource();
        setField("enableRoleCreation", true);
        stubRole("testrole005", SCOPE);
        stubRole("testrole110", SCOPE);

        keyManager.updateResourceScopes(null, Collections.singleton(SCOPE),
                Collections.singleton(localScope(SCOPE, "Internal/testrole005")),
                Collections.emptySet(), Collections.emptySet());

        ArgumentCaptor<WSO2IS7PatchRoleOperationInfo> patch =
                ArgumentCaptor.forClass(WSO2IS7PatchRoleOperationInfo.class);
        verify(rolesClient).patchRole(eq("id-testrole110"), patch.capture());
        assertTrue(patch.getValue().getOperations().get(0).getValue().getPermissions().isEmpty());
        verify(rolesClient, never()).patchRole(eq("id-testrole005"), any());
    }

    @Test
    public void testUpdateResourceScopesByIdRemovesBindingOfRoleBeyondFirstPage() throws Exception {
        useScopeResource();
        setField("enableRoleCreation", true);
        setField("manageScopesById", true);
        stubRole("testrole005", SCOPE);
        stubRole("testrole110", SCOPE);

        keyManager.updateResourceScopes(null, Collections.singleton(SCOPE),
                Collections.singleton(localScope(SCOPE, "Internal/testrole110")),
                Collections.emptySet(), Collections.emptySet());

        Field field = WSO2IS7KeyManager.class.getDeclaredField("wso2IS7APIResourceManagementClient");
        field.setAccessible(true);
        WSO2IS7APIResourceManagementClient apiResourceClient =
                (WSO2IS7APIResourceManagementClient) field.get(keyManager);
        verify(apiResourceClient).patchAPIResourceScopeById(eq("resource-id"), eq("scope-id"), any());
        ArgumentCaptor<WSO2IS7PatchRoleOperationInfo> patch =
                ArgumentCaptor.forClass(WSO2IS7PatchRoleOperationInfo.class);
        verify(rolesClient).patchRole(eq("id-testrole005"), patch.capture());
        assertTrue(patch.getValue().getOperations().get(0).getValue().getPermissions().isEmpty());
        verify(rolesClient, never()).patchRole(eq("id-testrole110"), any());
    }

    @Test
    public void testRegisterScopeBindsRoleBeyondFirstPage() throws Exception {
        useScopeResource();
        setField("enableRoleCreation", true);
        stubRole("testrole005", SCOPE);

        keyManager.registerScope(localScope("new_scope", "Internal/testrole005"));

        // A new scope needs only the filtered role lookup, which must find a role beyond the first page.
        ArgumentCaptor<JsonObject> payload = ArgumentCaptor.forClass(JsonObject.class);
        verify(rolesClient, times(1)).searchRoles(payload.capture());
        assertEquals("displayName eq testrole005", payload.getValue().get("filter").getAsString());
        ArgumentCaptor<WSO2IS7PatchRoleOperationInfo> patch =
                ArgumentCaptor.forClass(WSO2IS7PatchRoleOperationInfo.class);
        verify(rolesClient).patchRole(eq("id-testrole005"), patch.capture());
        List<WSO2IS7PatchRoleOperationInfo.Permission> permissions =
                patch.getValue().getOperations().get(0).getValue().getPermissions();
        assertEquals(2, permissions.size());
        assertEquals("new_scope", permissions.get(1).getValue());
        verify(rolesClient, never()).createRole(any());
    }

    @Test
    public void testRegisterScopeCreatesRoleWhenRoleSearchHasNoResources() throws Exception {
        useScopeResource();
        setField("enableRoleCreation", true);
        JsonObject emptyResponse = new JsonObject();
        emptyResponse.addProperty("totalResults", 0);
        when(rolesClient.searchRoles(any(JsonObject.class))).thenReturn(emptyResponse);

        keyManager.registerScope(localScope("new_scope", "Internal/absentrole"));

        ArgumentCaptor<WSO2IS7RoleInfo> role = ArgumentCaptor.forClass(WSO2IS7RoleInfo.class);
        verify(rolesClient).createRole(role.capture());
        assertEquals("absentrole", role.getValue().getDisplayName());
        assertEquals("new_scope", role.getValue().getPermissions().get(0).get("value"));
        verify(rolesClient, never()).getRole(any());
        verify(rolesClient, never()).patchRole(any(), any());
    }

    @Test
    public void testRegisterScopeSkipsAbsentRoleWhenRoleCreationIsDisabled() throws Exception {
        useScopeResource();

        keyManager.registerScope(localScope("new_scope", "absentrole"));

        verify(rolesClient, times(1)).searchRoles(any(JsonObject.class));
        verify(rolesClient, never()).createRole(any());
        verify(rolesClient, never()).patchRole(any(), any());
    }

    /**
     * Mocks an API resource holding the test scope and paged role search results.
     */
    private void useScopeResource() throws Exception {
        WSO2IS7APIResourceManagementClient apiResourceClient = mock(WSO2IS7APIResourceManagementClient.class);
        JsonObject apiResource = new JsonObject();
        apiResource.addProperty("id", "resource-id");
        JsonArray apiResources = new JsonArray();
        apiResources.add(apiResource);
        JsonObject apiResourcesResponse = new JsonObject();
        apiResourcesResponse.add("apiResources", apiResources);
        when(apiResourceClient.getAPIResources(any())).thenReturn(apiResourcesResponse);
        JsonObject scope = new JsonObject();
        scope.addProperty("id", "scope-id");
        scope.addProperty("name", SCOPE);
        scope.addProperty("displayName", SCOPE);
        scope.addProperty("description", "test");
        JsonArray scopes = new JsonArray();
        scopes.add(scope);
        when(apiResourceClient.getAPIResourceScopes("resource-id")).thenReturn(scopes);
        setField("wso2IS7APIResourceManagementClient", apiResourceClient);
        when(rolesClient.searchRoles(any(JsonObject.class))).thenAnswer(
                invocation -> pagedResponse(invocation.getArgument(0), TOTAL_ROLES, true));
    }

    /**
     * Returns a SCIM role search page of testrole001..testrole{total}, newest first, where testrole005 and
     * testrole110 hold the test scope.
     */
    private static JsonObject pagedResponse(JsonObject payload, int total, boolean includeTotalResults) {
        List<JsonObject> all = new ArrayList<>();
        for (int i = total; i >= 1; i--) {
            String name = String.format("testrole%03d", i);
            JsonObject role = new JsonObject();
            role.addProperty("id", "id-" + name);
            role.addProperty("displayName", name);
            JsonArray permissions = new JsonArray();
            if (i == 5 || i == 110) {
                JsonObject permission = new JsonObject();
                permission.addProperty("value", SCOPE);
                permissions.add(permission);
            }
            role.add("permissions", permissions);
            all.add(role);
        }
        if (payload.has("filter")) {
            String name = payload.get("filter").getAsString().replace("displayName eq ", "");
            List<JsonObject> matched = new ArrayList<>();
            for (JsonObject role : all) {
                if (name.equals(role.get("displayName").getAsString())) {
                    matched.add(role);
                }
            }
            all = matched;
        }
        int start = payload.has("startIndex") ? payload.get("startIndex").getAsInt() : 1;
        int count = payload.has("count") ? payload.get("count").getAsInt() : 100;
        JsonArray resources = new JsonArray();
        for (int i = start - 1; i < Math.min(all.size(), start - 1 + Math.min(count, 100)); i++) {
            resources.add(all.get(i));
        }
        JsonObject response = new JsonObject();
        if (includeTotalResults) {
            response.addProperty("totalResults", all.size());
        }
        response.add("Resources", resources);
        return response;
    }

    /**
     * Returns an APIM scope with the given key and comma separated role bindings.
     */
    private static Scope localScope(String key, String roles) {
        Scope scope = new Scope();
        scope.setKey(key);
        scope.setName(key);
        scope.setDescription("test");
        scope.setRoles(roles);
        return scope;
    }

    /**
     * Stubs the SCIM role lookup by ID for the given IS7 role, holding the given scopes as permissions.
     */
    private void stubRole(String name, String... scopes) throws Exception {
        WSO2IS7RoleInfo role = new WSO2IS7RoleInfo();
        role.setId("id-" + name);
        role.setDisplayName(name);
        List<Map<String, String>> permissions = new ArrayList<>();
        for (String scope : scopes) {
            permissions.add(Collections.singletonMap("value", scope));
        }
        role.setPermissions(permissions);
        when(rolesClient.getRole("id-" + name)).thenReturn(role);
    }

    private JsonArray searchRoles(String filter) throws Exception {
        Method method = WSO2IS7KeyManager.class.getDeclaredMethod("searchRoles", String.class);
        method.setAccessible(true);
        return (JsonArray) method.invoke(keyManager, filter);
    }

    private void setField(String name, Object value) throws Exception {
        Field field = WSO2IS7KeyManager.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(keyManager, value);
    }
}
