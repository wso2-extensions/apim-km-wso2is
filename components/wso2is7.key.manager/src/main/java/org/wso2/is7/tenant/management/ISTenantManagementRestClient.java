package org.wso2.is7.tenant.management;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;


/**
 * * REST Client for Managing Tenants in WSO2 Identity Server
 */
public class ISTenantManagementRestClient {
    private static final String TENANT_ID = "ID";
    private static final String TENANT_STATUS = "STATUS";
    private static final String TENANT_OWNER_ID = "OWNER_ID";
    private static final String TENANT_MANAGEMENT_RESOURCE_PATH = "api/server/v1/tenants/";

    public static void createTenantInIS(String identityServerBaseUrl, String admin, String adminPassword,
                                        String tenantDomain, String firstName,
                                        String lastName, String email, String identityUserName,
                                        String identityUserPassword) throws IOException {

        String endpoint = identityServerBaseUrl + TENANT_MANAGEMENT_RESOURCE_PATH;

        // JSON payload (no additional claims)
        String payload = String.format("{%n" +
                "  \"domain\": \"%s\",%n" +
                "  \"owners\": [%n" +
                "    {%n" +
                "      \"username\": \"%s\",%n" +
                "      \"password\": \"%s\",%n" +
                "      \"email\": \"%s\",%n" +
                "      \"firstname\": \"%s\",%n" +
                "      \"lastname\": \"%s\",%n" +
                "      \"provisioningMethod\": \"inline-password\"%n" +
                "    }%n" +
                "  ]%n" +
                "}", tenantDomain, admin, adminPassword, email, firstName, lastName);

        // Setup HTTP connection
        URL url = new URL(endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Accept", "*/*");
        connection.setRequestProperty("Content-Type", "application/json");


        // Set Basic Auth Header
        String auth = identityUserName + ":" + identityUserPassword;
        String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        connection.setRequestProperty("Authorization", "Basic " + encodedAuth);

        // Send request
        OutputStream outputStream = connection.getOutputStream();
        byte[] input = payload.getBytes(StandardCharsets.UTF_8);
        outputStream.write(input);


        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_CREATED) {
            throw new RuntimeException("Failed to create tenant in IS. HTTP response code: " + responseCode);
        }
    }

    public static void updateTenantInIS(String identityServerBaseUrl, String tenantDomain, String adminPassword,
                                        String firstName, String lastName, String email, String identityUserName,
                                        String identityUserPassword) throws IOException {

        Map<String, String> tenantInfoMap = getTenantIdAStatusAndOwnerInIS(identityServerBaseUrl, tenantDomain,
                identityUserName, identityUserPassword);

        //TODO : remove this API call after IS fixes https://github.com/wso2-enterprise/wso2-iam-internal/issues/3992
        tenantInfoMap.put(TENANT_OWNER_ID, getTenantOwnerId(identityServerBaseUrl, tenantInfoMap.get(TENANT_ID),
                identityUserName, identityUserPassword));

        String endpoint = identityServerBaseUrl + TENANT_MANAGEMENT_RESOURCE_PATH + tenantInfoMap.get(TENANT_ID) +
                "/owners/" + tenantInfoMap.get(TENANT_OWNER_ID);

        // JSON payload
        String payload = String.format("{%n" +
                "  \"email\": \"%s\",%n" +
                "  \"password\": \"%s\",%n" +
                "  \"firstname\": \"%s\",%n" +
                "  \"lastname\": \"%s\"%n" +
                "}", email, adminPassword, firstName, lastName);

        // Setup HTTP connection
        URL url = new URL(endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("PUT");
        connection.setRequestProperty("Accept", "*/*");
        connection.setRequestProperty("Content-Type", "application/json");

        // Set Basic Auth Header
        String auth = identityUserName + ":" + identityUserPassword;
        String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        connection.setRequestProperty("Authorization", "Basic " + encodedAuth);

        // Send request
        OutputStream outputStream = connection.getOutputStream();
        byte[] input = payload.getBytes(StandardCharsets.UTF_8);
        outputStream.write(input);

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Failed to update tenant in IS. HTTP response code: " + responseCode);
        }
    }

    //TODO : remove this API call after IS fixes https://github.com/wso2-enterprise/wso2-iam-internal/issues/3992
    private static String getTenantOwnerId(String identityServerBaseUrl, String tenantId, String identityUserName,
                                           String identityUserPassword) throws IOException {
        String endpoint = identityServerBaseUrl + TENANT_MANAGEMENT_RESOURCE_PATH + tenantId + "/owners";

        URL url = new URL(endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Accept", "application/json");

        // Add Basic Auth
        String auth = identityUserName + ":" + identityUserPassword;
        String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        connection.setRequestProperty("Authorization", "Basic " + encodedAuth);

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Failed to fetch tenant details. HTTP response code: " + responseCode);
        }

        // Properly handle input stream with try-with-resources
        InputStream inputStream = connection.getInputStream();
        try (InputStreamReader isr = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
             BufferedReader reader = new BufferedReader(isr)) {

            StringBuilder responseContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                responseContent.append(line);
            }

            JsonArray jsonResponse = new JsonParser().parse(responseContent.toString()).getAsJsonArray();
            return jsonResponse.get(0).getAsJsonObject().get("id").getAsString();
        }
    }

    private static Map<String, String> getTenantIdAStatusAndOwnerInIS(String identityServerBaseUrl, String tenantDomain,
                                                                      String identityUserName,
                                                                      String identityUserPassword) throws IOException {
        Map<String, String> tenantIdStatusMap = new HashMap<>();
        String endpoint = identityServerBaseUrl + TENANT_MANAGEMENT_RESOURCE_PATH + tenantDomain;

        URL url = new URL(endpoint);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Accept", "application/json");

        // Add Basic Auth
        String auth = identityUserName + ":" + identityUserPassword;
        String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        connection.setRequestProperty("Authorization", "Basic " + encodedAuth);

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Failed to fetch tenant details. HTTP response code: " + responseCode);
        }

        // Properly handle input stream with try-with-resources
        InputStream inputStream = connection.getInputStream();
        try (InputStreamReader isr = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
             BufferedReader reader = new BufferedReader(isr)) {

            StringBuilder responseContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                responseContent.append(line);
            }

            JsonObject jsonResponse = new JsonParser().parse(responseContent.toString()).getAsJsonObject();
            tenantIdStatusMap.put(TENANT_ID, jsonResponse.get("id").getAsString());
            tenantIdStatusMap.put(TENANT_STATUS, jsonResponse.get("lifecycleStatus").getAsJsonObject().get("activated")
                    .getAsString());
            tenantIdStatusMap.put(TENANT_OWNER_ID, jsonResponse.get("owners").getAsJsonArray().get(0)
                    .getAsJsonObject().get("id").getAsString());
            return tenantIdStatusMap;
        }
    }

    public static void updateTenantStatusInIS(String identityServerBaseUrl, String tenantDomain,
                                              boolean isActive, String identityUserName,
                                              String identityUserPassword) throws IOException {

        Map<String, String> tenantInfoMap = getTenantIdAStatusAndOwnerInIS(identityServerBaseUrl, tenantDomain,
                identityUserName, identityUserPassword);

        String endpoint = identityServerBaseUrl + TENANT_MANAGEMENT_RESOURCE_PATH + tenantInfoMap.get(TENANT_ID)
                + "/lifecycle-status";

        //check if tenant is already active
        if (isActive != Boolean.parseBoolean(tenantInfoMap.get(TENANT_STATUS))) {
            // JSON payload
            String payload = String.format("{\"activated\": %s}", isActive);

            // Setup HTTP connection
            URL url = new URL(endpoint);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setRequestMethod("PUT");
            connection.setRequestProperty("Accept", "*/*");
            connection.setRequestProperty("Content-Type", "application/json");

            // Set Basic Auth Header
            String auth = identityUserName + ":" + identityUserPassword;
            String encodedAuth = java.util.Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
            connection.setRequestProperty("Authorization", "Basic " + encodedAuth);

            // Send request
            OutputStream outputStream = connection.getOutputStream();
            byte[] input = payload.getBytes(StandardCharsets.UTF_8);
            outputStream.write(input);

            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new RuntimeException("Failed to update tenant status in IS. HTTP response code: " + responseCode);
            }
        }
    }
}


