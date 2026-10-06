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

import com.google.gson.JsonParser;
import org.junit.Before;
import org.junit.Test;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.dto.UserInfoDTO;
import org.wso2.carbon.apimgt.impl.kmclient.model.Claim;
import org.wso2.carbon.apimgt.impl.kmclient.model.ClaimsList;
import org.wso2.carbon.apimgt.impl.kmclient.model.UserClient;
import org.wso2.is7.client.model.WSO2IS7SCIMMeClient;
import org.wso2.is7.client.model.WSO2IS7SCIMSchemasClient;
import org.wso2.is7.client.utils.ClaimMappingReader;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for the user claims returned by WSO2IS7KeyManager#getUserClaims, for both supported UserInfo endpoints.
 */
public class WSO2IS7KeyManagerUserClaimsTest {

    private static final String LOCAL_DIALECT = "http://wso2.org/claims/";
    private static final String SCIM2_USER = "urn:ietf:params:scim:schemas:core:2.0:User:";
    private static final String SCIM2_CUSTOM = "urn:scim:schemas:extension:custom:User";

    private static final String SCIM_ME_RESPONSE = "{"
            + "\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\",\"" + SCIM2_CUSTOM + "\"],"
            + "\"id\":\"1e2a3b4c\",\"userName\":\"claimuser\",\"name\":{\"givenName\":\"Claire\"},"
            + "\"" + SCIM2_CUSTOM + "\":{\"department\":\"Support\"}}";
    private static final String SCIM_SCHEMAS_RESPONSE = "[{\"id\":\"" + SCIM2_CUSTOM + "\",\"name\":\"User\","
            + "\"attributes\":[{\"name\":\"department\",\"type\":\"string\",\"multiValued\":false}]}]";

    private WSO2IS7KeyManager keyManager;
    private KeyManagerConfiguration configuration;
    private Map<String, String> defaultClaimMappings;

    @Before
    public void setUp() throws Exception {
        // A mock that calls real methods avoids the field initializers, which need a running server.
        keyManager = mock(WSO2IS7KeyManager.class, CALLS_REAL_METHODS);
        configuration = new KeyManagerConfiguration();
        configuration.addParameter("claim_mappings", new ArrayList<Map<String, String>>());
        setField(AbstractKeyManager.class, "configuration", configuration);
        defaultClaimMappings = ClaimMappingReader.loadClaimMappings();
        setField(WSO2IS7KeyManager.class, "claimMappings", defaultClaimMappings);
    }

    @Test
    public void testUserInfoEndpointClaimsAreNotDropped() throws Exception {
        useUserInfoEndpoint(claim(LOCAL_DIALECT + "givenname", "Claire"),
                claim(LOCAL_DIALECT + "organization", "WSO2"));

        Map<String, String> userClaims = keyManager.getUserClaims("claimuser", properties());

        assertEquals(2, userClaims.size());
        assertEquals("Claire", userClaims.get(LOCAL_DIALECT + "givenname"));
        assertEquals("WSO2", userClaims.get(LOCAL_DIALECT + "organization"));
    }

    @Test
    public void testUserInfoEndpointClaimsAreMapped() throws Exception {
        useUserInfoEndpoint(claim(LOCAL_DIALECT + "givenname", "Claire"),
                claim(LOCAL_DIALECT + "organization", "WSO2"));
        configureClaimMapping(LOCAL_DIALECT + "givenname", LOCAL_DIALECT + "firstname");

        Map<String, String> userClaims = keyManager.getUserClaims("claimuser", properties());

        assertEquals(2, userClaims.size());
        assertEquals("Claire", userClaims.get(LOCAL_DIALECT + "firstname"));
        assertFalse(userClaims.containsKey(LOCAL_DIALECT + "givenname"));
        assertEquals("WSO2", userClaims.get(LOCAL_DIALECT + "organization"));
    }

    @Test
    public void testUserInfoEndpointClaimsWithoutConfiguredClaimMappings() throws Exception {
        removeConfiguredClaimMappings();
        useUserInfoEndpoint(claim(LOCAL_DIALECT + "givenname", "Claire"));

        Map<String, String> userClaims = keyManager.getUserClaims("claimuser", properties());

        assertEquals("Claire", userClaims.get(LOCAL_DIALECT + "givenname"));
    }

    @Test
    public void testScimMeUnmappedClaimsAreDroppedByDefault() throws Exception {
        useScimMeEndpoint();

        Map<String, String> userClaims = keyManager.getUserClaims("claimuser", properties());

        assertEquals("claimuser", userClaims.get(LOCAL_DIALECT + "username"));
        assertEquals("Claire", userClaims.get(LOCAL_DIALECT + "givenname"));
        assertFalse(userClaims.containsKey(SCIM2_CUSTOM + ":department"));
        assertFalse(userClaims.containsKey(SCIM2_USER + "userName"));
    }

    @Test
    public void testScimMeUnmappedClaimsArePassedThroughWhenEnabled() throws Exception {
        useScimMeEndpoint();
        setField(WSO2IS7KeyManager.class, "passThroughUnmappedScim2Claims", true);

        Map<String, String> userClaims = keyManager.getUserClaims("claimuser", properties());

        assertEquals("claimuser", userClaims.get(LOCAL_DIALECT + "username"));
        assertEquals("Claire", userClaims.get(LOCAL_DIALECT + "givenname"));
        assertEquals("Support", userClaims.get(SCIM2_CUSTOM + ":department"));
        assertFalse(userClaims.containsKey(SCIM2_USER + "userName"));
    }

    @Test
    public void testScimMeConfiguredClaimMappingIsAppliedWhenPassThroughEnabled() throws Exception {
        useScimMeEndpoint();
        setField(WSO2IS7KeyManager.class, "passThroughUnmappedScim2Claims", true);
        configureClaimMapping(SCIM2_CUSTOM + ":department", LOCAL_DIALECT + "department");

        Map<String, String> userClaims = keyManager.getUserClaims("claimuser", properties());

        assertEquals("Support", userClaims.get(LOCAL_DIALECT + "department"));
        assertFalse(userClaims.containsKey(SCIM2_CUSTOM + ":department"));
    }

    @Test
    public void testMappedClaimTakesPrecedenceOverUnmappedClaimWithSameUri() throws Exception {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(LOCAL_DIALECT + "nickname", LOCAL_DIALECT + "title");

        Map<String, String> unmappedFirst = new LinkedHashMap<>();
        unmappedFirst.put(LOCAL_DIALECT + "title", "Engineer");
        unmappedFirst.put(LOCAL_DIALECT + "nickname", "cu");
        Map<String, String> mappedFirst = new LinkedHashMap<>();
        mappedFirst.put(LOCAL_DIALECT + "nickname", "cu");
        mappedFirst.put(LOCAL_DIALECT + "title", "Engineer");

        for (Map<String, String> claims : new Map[]{unmappedFirst, mappedFirst}) {
            Map<String, String> result = invokeGetMappedAttributes(claims, mappings, true);
            assertEquals(1, result.size());
            assertEquals("cu", result.get(LOCAL_DIALECT + "title"));
        }
    }

    @Test
    public void testGetClaimMappingsDoesNotModifyDefaultClaimMappings() throws Exception {
        int defaultSize = defaultClaimMappings.size();
        configureClaimMapping(LOCAL_DIALECT + "givenname", LOCAL_DIALECT + "firstname");

        Map<String, String> claimMappings = invokeGetClaimMappings();

        assertNotSame(defaultClaimMappings, claimMappings);
        assertEquals(LOCAL_DIALECT + "firstname", claimMappings.get(LOCAL_DIALECT + "givenname"));
        assertEquals(defaultSize, defaultClaimMappings.size());
        assertNull(defaultClaimMappings.get(LOCAL_DIALECT + "givenname"));
    }

    @Test
    public void testGetClaimMappingsWithoutConfiguredClaimMappings() throws Exception {
        removeConfiguredClaimMappings();

        Map<String, String> claimMappings = invokeGetClaimMappings();

        assertEquals(defaultClaimMappings, claimMappings);
        assertTrue(claimMappings.containsKey(SCIM2_USER + "userName"));
    }

    private void useUserInfoEndpoint(Claim... claims) throws Exception {
        ClaimsList claimsList = new ClaimsList();
        List<Claim> list = new ArrayList<>();
        for (Claim claim : claims) {
            list.add(claim);
        }
        claimsList.setList(list);
        claimsList.setCount(list.size());
        UserClient userClient = mock(UserClient.class);
        when(userClient.generateClaims(any(UserInfoDTO.class))).thenReturn(claimsList);
        setField(WSO2IS7KeyManager.class, "userClient", userClient);
        setField(WSO2IS7KeyManager.class, "isUserInfoEndpointScimMe", false);
    }

    private void useScimMeEndpoint() throws Exception {
        WSO2IS7SCIMMeClient scimMeClient = mock(WSO2IS7SCIMMeClient.class);
        when(scimMeClient.getMe(anyString())).thenReturn(new JsonParser().parse(SCIM_ME_RESPONSE).getAsJsonObject());
        WSO2IS7SCIMSchemasClient scimSchemasClient = mock(WSO2IS7SCIMSchemasClient.class);
        when(scimSchemasClient.getSchemas(anyString()))
                .thenReturn(new JsonParser().parse(SCIM_SCHEMAS_RESPONSE).getAsJsonArray());
        setField(WSO2IS7KeyManager.class, "wso2IS7SCIMMeClient", scimMeClient);
        setField(WSO2IS7KeyManager.class, "wso2IS7SCIMSchemasClient", scimSchemasClient);
        setField(WSO2IS7KeyManager.class, "isUserInfoEndpointScimMe", true);
    }

    private void configureClaimMapping(String remoteClaim, String localClaim) {
        Map<String, String> claimMapping = new HashMap<>();
        claimMapping.put("remoteClaim", remoteClaim);
        claimMapping.put("localClaim", localClaim);
        List<Map<String, String>> claimMappings = new ArrayList<>();
        claimMappings.add(claimMapping);
        configuration.addParameter("claim_mappings", claimMappings);
    }

    private void removeConfiguredClaimMappings() throws Exception {
        configuration = new KeyManagerConfiguration();
        setField(AbstractKeyManager.class, "configuration", configuration);
    }

    private static Map<String, Object> properties() {
        Map<String, Object> properties = new HashMap<>();
        properties.put(APIConstants.KeyManager.ACCESS_TOKEN, "access-token");
        properties.put(APIConstants.KeyManager.CLAIM_DIALECT, "http://wso2.org/claims");
        return properties;
    }

    private static Claim claim(String uri, String value) {
        Claim claim = new Claim();
        claim.setUri(uri);
        claim.setValue(value);
        return claim;
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> invokeGetClaimMappings() throws Exception {
        Method method = WSO2IS7KeyManager.class.getDeclaredMethod("getClaimMappings");
        method.setAccessible(true);
        return (Map<String, String>) method.invoke(keyManager);
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> invokeGetMappedAttributes(Map<String, String> claims, Map<String, String> mappings,
                                                          boolean includeUnmappedClaims) throws Exception {
        Method method = WSO2IS7KeyManager.class.getDeclaredMethod("getMappedAttributes", Map.class, Map.class,
                boolean.class);
        method.setAccessible(true);
        return (Map<String, String>) method.invoke(keyManager, claims, mappings, includeUnmappedClaims);
    }

    private void setField(Class<?> declaringClass, String name, Object value) throws Exception {
        Field field = declaringClass.getDeclaredField(name);
        field.setAccessible(true);
        field.set(keyManager, value);
    }
}
