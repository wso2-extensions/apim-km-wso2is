/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
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

package org.wso2.is7.client;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import feign.Feign;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.ExceptionCodes;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.certificatemgt.TrustStoreUtils;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.kmclient.ApacheFeignHttpClient;
import org.wso2.carbon.apimgt.impl.kmclient.FormEncoder;
import org.wso2.carbon.apimgt.impl.kmclient.KMClientErrorDecoder;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;
import org.wso2.carbon.apimgt.impl.kmclient.model.AuthClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.IntrospectInfo;
import org.wso2.carbon.apimgt.impl.kmclient.model.IntrospectionClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.TenantHeaderInterceptor;
import org.wso2.carbon.apimgt.impl.kmclient.model.TokenInfo;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.impl.utils.CertificateMgtUtils;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import org.wso2.is7.client.model.WSO2IS7APIResourceInfo;
import org.wso2.is7.client.model.WSO2IS7APIResourceManagementClient;
import org.wso2.is7.client.model.WSO2IS7APIResourceScopeInfo;
import org.wso2.is7.client.model.WSO2IS7ClientInfo;
import org.wso2.is7.client.model.WSO2IS7DCRClient;
import org.wso2.is7.client.model.WSO2IS7PatchRoleOperationInfo;
import org.wso2.is7.client.model.WSO2IS7RoleInfo;
import org.wso2.is7.client.model.WSO2IS7SCIMMeClient;
import org.wso2.is7.client.model.WSO2IS7SCIMRolesClient;
import org.wso2.is7.client.model.WSO2IS7SCIMSchemasClient;
import org.wso2.is7.client.utils.AttributeMapper;
import org.wso2.is7.client.utils.ClaimMappingReader;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import static org.wso2.carbon.apimgt.impl.utils.APIUtil.getTenantIdFromTenantDomain;

/**
 * This class provides the implementation to use WSO2 Identity Server 7 for managing OAuth clients and Tokens
 * needed by WSO2 API Manager.
 * NOTE: Some of the methods (stated in comments above the respective method definitions) are copied from
 * https://raw.githubusercontent.com/wso2/carbon-apimgt/v9.29.35/components/apimgt/org.wso2.carbon.apimgt.impl/src/main/java/org/wso2/carbon/apimgt/impl/AMDefaultKeyManagerImpl.java
 * to avoid being dependent on carbon-apimgt.
 */
public class WSO2IS7KeyManager extends AbstractKeyManager {
    private static final Log log = LogFactory.getLog(WSO2IS7KeyManager.class);

    private static final String API_RESOURCE_MANAGEMENT_ENDPOINT = "api_resource_management_endpoint";
    private static final String IS7_ROLES_ENDPOINT = "is7_roles_endpoint";
    private static final String ENABLE_ROLES_CREATION = "enable_roles_creation";
    private static final String GRANT_TYPE_VALUE = "client_credentials";
    private static final String DEFAULT_OAUTH_2_RESOURCE_NAME = "User-defined OAuth2 Resource";
    private static final String DEFAULT_OAUTH_2_RESOURCE_DESCRIPTION = "This is Default OAuth2 Resource Representation";
    private static final String SEARCH_REQUEST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
    private static final String CLAIM_MAPPINGS_CONFIG_PARAMETER = "claim_mappings";
    private static final String REMOTE_CLAIM = "remoteClaim";
    private static final String LOCAL_CLAIM = "localClaim";
    private static final long USER_SCHEMA_CACHE_EXPIRY = 3600L;

    // Name of the default API Resource of WSO2 IS7 - which is used to contain scopes.
    private static final String DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER = "User-defined-oauth2-resource";
    private static final String WSO2_IDENTITY_USER_HEADER = "WSO2-Identity-User";
    private static final String TRUST_STORE_LOCATION = "Security.TrustStore.Location";
    private static final String TRUST_STORE_PASSWORD = "Security.TrustStore.Password";
    private static final String KEY_STORE_LOCATION = "Security.KeyStore.Location";
    private static final String KEY_STORE_TYPE = "Security.KeyStore.Type";
    private static final String KEY_STORE_PASSWORD = "Security.KeyStore.Password";
    private static final String JAVAX_NET_SSL_TRUST_STORE = "javax.net.ssl.trustStore";
    private static final String JAVAX_NET_SSL_TRUST_STORE_PASSWORD = "javax.net.ssl.trustStorePassword";
    private static final String TLS = "TLS";
    private static final String TLS_V1_2 = "TLSv1.2";
    private static final String TLS_V1_3 = "TLSv1.3";

    private boolean enableRoleCreation = false;

    private WSO2IS7DCRClient wso2IS7DCRClient;
    private IntrospectionClient introspectionClient;
    private AuthClient authClient;
    private WSO2IS7APIResourceManagementClient wso2IS7APIResourceManagementClient;
    private WSO2IS7SCIMRolesClient wso2IS7SCIMRolesClient;
    private WSO2IS7SCIMMeClient wso2IS7SCIMMeClient;
    private WSO2IS7SCIMSchemasClient wso2IS7SCIMSchemasClient;
    private Map<String, String> claimMappings;
    private CertificateMgtUtils certificateMgtUtils = CertificateMgtUtils.getInstance();
    private static String certificateType = "X.509";


    /* Copied from AMDefaultKeyManagerImpl. WSO2IS7ClientInfo is used instead of ClientInfo. */
    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
        // OAuthApplications are created by calling to APIKeyMgtSubscriber Service
        OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();

        // Subscriber's name should be passed as a parameter, since it's under the subscriber the OAuth App is created.
        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.
                OAUTH_CLIENT_USERNAME);

        if (StringUtils.isEmpty(userId)) {
            throw new APIManagementException("Missing user ID for OAuth application creation.");
        }

        String applicationName = oAuthApplicationInfo.getClientName();
        String oauthClientName = oauthAppRequest.getOAuthApplicationInfo().getApplicationUUID();
        String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);

        if (StringUtils.isNotEmpty(applicationName) && StringUtils.isNotEmpty(keyType)) {
            String domain = UserCoreUtil.extractDomainFromName(userId);
            if (domain != null && !domain.isEmpty() && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(domain)) {
                userId = userId.replace(UserCoreConstants.DOMAIN_SEPARATOR, "_");
            }
            oauthClientName = String.format("%s_%s_%s", APIUtil.replaceEmailDomain(MultitenantUtils.
                    getTenantAwareUsername(userId)), oauthClientName, keyType);
        } else {
            throw new APIManagementException("Missing required information for OAuth application creation.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Trying to create OAuth application : " + oauthClientName + " for application: " +
                    applicationName + " and key type: " + keyType);
        }

        String tokenScope = (String) oAuthApplicationInfo.getParameter("tokenScope");
        String[] tokenScopes = new String[1];
        tokenScopes[0] = tokenScope;

        WSO2IS7ClientInfo request = createClientInfo(oAuthApplicationInfo, oauthClientName, false);
        WSO2IS7ClientInfo createdClient;

        try {
            createdClient = wso2IS7DCRClient.createApplication(request);
            buildDTOFromClientInfo(createdClient, oAuthApplicationInfo);

            oAuthApplicationInfo.addParameter("tokenScope", tokenScopes);
            oAuthApplicationInfo.setIsSaasApplication(false);

            return oAuthApplicationInfo;

        } catch (KeyManagerClientException e) {
            handleException(
                    "Can not create OAuth application  : " + oauthClientName + " for application: " + applicationName
                            + " and key type: " + keyType, e);
            return null;
        }
    }

    /**
     * Copied from AMDefaultKeyManagerImpl. WSO2IS7ClientInfo is used instead of ClientInfo.
     * Construct ClientInfo object for application create request
     *
     * @param info            The OAuthApplicationInfo object
     * @param oauthClientName The name of the OAuth application to be created
     * @param isUpdate        To determine whether the ClientInfo object is related to application update call
     * @return constructed ClientInfo object
     * @throws JSONException          for errors in parsing the OAuthApplicationInfo json string
     * @throws APIManagementException if an error occurs while constructing the ClientInfo object
     */
    private WSO2IS7ClientInfo createClientInfo(OAuthApplicationInfo info, String oauthClientName, boolean isUpdate)
            throws JSONException, APIManagementException {

        WSO2IS7ClientInfo clientInfo = new WSO2IS7ClientInfo();
        JSONObject infoJson = new JSONObject(info.getJsonString());
        if (infoJson.has(ApplicationConstants.OAUTH_CLIENT_GRANT)) {
            // this is done as there are instances where the grant string begins with a comma character.
            String grantString = infoJson.getString(ApplicationConstants.OAUTH_CLIENT_GRANT);
            if (grantString.startsWith(",")) {
                grantString = grantString.substring(1);
            }
            String[] grantTypes = grantString.split(",");
            clientInfo.setGrantTypes(Arrays.asList(grantTypes));
        }
        if (StringUtils.isNotEmpty(info.getCallBackURL())) {
            String callBackURL = info.getCallBackURL();
            String[] callbackURLs = callBackURL.trim().split("\\s*,\\s*");
            clientInfo.setRedirectUris(Arrays.asList(callbackURLs));
        }

        clientInfo.setClientName(oauthClientName);

        if (APIConstants.JWT.equals(info.getTokenType())) {
            clientInfo.setTokenTypeExtension(info.getTokenType());
        } else {
            clientInfo.setTokenTypeExtension(APIConstants.TOKEN_TYPE_DEFAULT);
        }

        if (StringUtils.isNotEmpty(info.getClientId())) {
            if (isUpdate) {
                clientInfo.setClientId(info.getClientId());
            } else {
                clientInfo.setPresetClientId(info.getClientId());
            }
        }
        if (StringUtils.isNotEmpty(info.getClientSecret())) {
            if (isUpdate) {
                clientInfo.setClientSecret(info.getClientSecret());
            } else {
                clientInfo.setPresetClientSecret(info.getClientSecret());
            }
        }
        Object parameter = info.getParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES);
        Map<String, Object> additionalProperties = new HashMap<>();
        if (parameter instanceof String) {
            additionalProperties = new Gson().fromJson((String) parameter, Map.class);
        }
        if (additionalProperties.containsKey(WSO2IS7KeyManagerConstants.APPLICATION_TOKEN_LIFETIME)) {
            Object expiryTimeObject =
                    additionalProperties.get(WSO2IS7KeyManagerConstants.APPLICATION_TOKEN_LIFETIME);
            if (expiryTimeObject instanceof String) {
                if (!APIConstants.KeyManager.NOT_APPLICABLE_VALUE.equals(expiryTimeObject)) {
                    try {
                        long expiry = Long.parseLong((String) expiryTimeObject);
                        if (expiry < 0) {
                            throw new APIManagementException("Invalid application token lifetime given for "
                                    + oauthClientName, ExceptionCodes.INVALID_APPLICATION_PROPERTIES);
                        }
                        clientInfo.setApplicationTokenLifetime(expiry);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }
        if (additionalProperties.containsKey(WSO2IS7KeyManagerConstants.USER_TOKEN_LIFETIME)) {
            Object expiryTimeObject =
                    additionalProperties.get(WSO2IS7KeyManagerConstants.USER_TOKEN_LIFETIME);
            if (expiryTimeObject instanceof String) {
                if (!APIConstants.KeyManager.NOT_APPLICABLE_VALUE.equals(expiryTimeObject)) {
                    try {
                        long expiry = Long.parseLong((String) expiryTimeObject);
                        if (expiry < 0) {
                            throw new APIManagementException("Invalid user token lifetime given for "
                                    + oauthClientName, ExceptionCodes.INVALID_APPLICATION_PROPERTIES);
                        }
                        clientInfo.setUserTokenLifetime(expiry);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }
        if (additionalProperties.containsKey(WSO2IS7KeyManagerConstants.REFRESH_TOKEN_LIFETIME)) {
            Object expiryTimeObject =
                    additionalProperties.get(WSO2IS7KeyManagerConstants.REFRESH_TOKEN_LIFETIME);
            if (expiryTimeObject instanceof String) {
                if (!APIConstants.KeyManager.NOT_APPLICABLE_VALUE.equals(expiryTimeObject)) {
                    try {
                        long expiry = Long.parseLong((String) expiryTimeObject);
                        clientInfo.setRefreshTokenLifetime(expiry);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }
        if (additionalProperties.containsKey(WSO2IS7KeyManagerConstants.ID_TOKEN_LIFETIME)) {
            Object expiryTimeObject =
                    additionalProperties.get(WSO2IS7KeyManagerConstants.ID_TOKEN_LIFETIME);
            if (expiryTimeObject instanceof String) {
                if (!APIConstants.KeyManager.NOT_APPLICABLE_VALUE.equals(expiryTimeObject)) {
                    try {
                        long expiry = Long.parseLong((String) expiryTimeObject);
                        clientInfo.setIdTokenLifetime(expiry);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }

        if (additionalProperties.containsKey(WSO2IS7KeyManagerConstants.PKCE_MANDATORY)) {
            Object pkceMandatoryValue =
                    additionalProperties.get(WSO2IS7KeyManagerConstants.PKCE_MANDATORY);
            if (pkceMandatoryValue instanceof String) {
                if (!WSO2IS7KeyManagerConstants.PKCE_MANDATORY.equals(pkceMandatoryValue)) {
                    try {
                        Boolean pkceMandatory = Boolean.parseBoolean((String) pkceMandatoryValue);
                        clientInfo.setPkceMandatory(pkceMandatory);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }

        if (additionalProperties.containsKey(WSO2IS7KeyManagerConstants.PKCE_SUPPORT_PLAIN)) {
            Object pkceSupportPlainValue =
                    additionalProperties.get(WSO2IS7KeyManagerConstants.PKCE_SUPPORT_PLAIN);
            if (pkceSupportPlainValue instanceof String) {
                if (!WSO2IS7KeyManagerConstants.PKCE_SUPPORT_PLAIN.equals(pkceSupportPlainValue)) {
                    try {
                        Boolean pkceSupportPlain = Boolean.parseBoolean((String) pkceSupportPlainValue);
                        clientInfo.setPkceSupportPlain(pkceSupportPlain);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }

        if (additionalProperties.containsKey(WSO2IS7KeyManagerConstants.PUBLIC_CLIENT)) {
            Object bypassClientCredentialsValue =
                    additionalProperties.get(WSO2IS7KeyManagerConstants.PUBLIC_CLIENT);
            if (bypassClientCredentialsValue instanceof String) {
                if (!WSO2IS7KeyManagerConstants.PUBLIC_CLIENT.equals(bypassClientCredentialsValue)) {
                    try {
                        Boolean bypassClientCredentials = Boolean.parseBoolean((String) bypassClientCredentialsValue);
                        clientInfo.setExtPublicClient(bypassClientCredentials);
                    } catch (NumberFormatException e) {
                        // No need to throw as its due to not a number sent.
                    }
                }
            }
        }

        // Set the display name of the application. This name would appear in the consent page of the app.
        clientInfo.setApplicationDisplayName(info.getClientName());
        clientInfo.setExtAllowedAudience("organization");
        return clientInfo;
    }

    /* Copied from AMDefaultKeyManagerImpl. WSO2IS7ClientInfo is used instead of ClientInfo. */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest appInfoDTO) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = appInfoDTO.getOAuthApplicationInfo();

        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);
        String applicationName = oAuthApplicationInfo.getClientName();
        String oauthClientName = oAuthApplicationInfo.getApplicationUUID();
        String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);

        // First we attempt to get the tenant domain from the userID and if it is not possible, we fetch it
        // from the ThreadLocalCarbonContext

        if (StringUtils.isNotEmpty(applicationName) && StringUtils.isNotEmpty(keyType)) {
            // Replace the domain name separator with an underscore for secondary user stores
            String domain = UserCoreUtil.extractDomainFromName(userId);
            if (domain != null && !domain.isEmpty() && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(domain)) {
                userId = userId.replace(UserCoreConstants.DOMAIN_SEPARATOR, "_");
            }
            // Construct the application name subsequent to replacing email domain separator
            oauthClientName = String.format("%s_%s_%s", APIUtil.replaceEmailDomain(MultitenantUtils.
                    getTenantAwareUsername(userId)), oauthClientName, keyType);
        } else {
            throw new APIManagementException("Missing required information for OAuth application update.");
        }

        log.debug("Updating OAuth Client with ID : " + oAuthApplicationInfo.getClientId());
        if (log.isDebugEnabled() && oAuthApplicationInfo.getCallBackURL() != null) {
            log.debug("CallBackURL : " + oAuthApplicationInfo.getCallBackURL());
        }
        if (log.isDebugEnabled() && applicationName != null) {
            log.debug("Client Name : " + oauthClientName);
        }

        WSO2IS7ClientInfo request = createClientInfo(oAuthApplicationInfo, oauthClientName, true);
        WSO2IS7ClientInfo createdClient;
        try {
            createdClient = wso2IS7DCRClient.updateApplication(oAuthApplicationInfo.getClientId(), request);
            return buildDTOFromClientInfo(createdClient, new OAuthApplicationInfo());
        } catch (KeyManagerClientException e) {
            handleException("Error occurred while updating OAuth Client : ", e);
            return null;
        }
    }

    @Override
    public OAuthApplicationInfo updateApplicationOwner(OAuthAppRequest appInfoDTO, String owner)
            throws APIManagementException {

        return null; // Implementation is not applicable.
    }


    /* Copied from AMDefaultKeyManagerImpl. */
    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Trying to delete OAuth application for consumer key :" + consumerKey);
        }

        try {
            wso2IS7DCRClient.deleteApplication(consumerKey);
        } catch (KeyManagerClientException e) {
            handleException("Cannot remove service provider for the given consumer key : " + consumerKey, e);
        }
    }

    /* Copied from AMDefaultKeyManagerImpl. WSO2IS7ClientInfo is used instead of ClientInfo. */
    @Override
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Trying to retrieve OAuth application for consumer key :" + consumerKey);
        }

        try {
            WSO2IS7ClientInfo clientInfo = wso2IS7DCRClient.getApplication(consumerKey);
            return buildDTOFromClientInfo(clientInfo, new OAuthApplicationInfo());
        } catch (KeyManagerClientException e) {
            if (e.getStatusCode() == 404) {
                return null;
            }
            handleException("Cannot retrieve service provider for the given consumer key : " + consumerKey, e);
            return null;
        }
    }

    /* Copied from AMDefaultKeyManagerImpl. WSO2IS7ClientInfo is used instead of ClientInfo. */
    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {

        AccessTokenInfo tokenInfo;

        if (tokenRequest == null) {
            log.warn("No information available to generate Token.");
            return null;
        }

        //We do not revoke the previously obtained token anymore since we do not possess the access token.

        // When validity time set to a negative value, a token is considered never to expire.
        if (tokenRequest.getValidityPeriod() == OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) {
            // Setting a different -ve value if the set value is -1 (-1 will be ignored by TokenValidator)
            tokenRequest.setValidityPeriod(-2L);
        }

        //Generate New Access Token
        String scopes = String.join(" ", tokenRequest.getScope());
        TokenInfo tokenResponse;

        try {
            String credentials = tokenRequest.getClientId() + ':' + tokenRequest.getClientSecret();
            String authToken = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            if (APIConstants.OAuthConstants.TOKEN_EXCHANGE.equals(tokenRequest.getGrantType())) {
                tokenResponse = authClient.generate(tokenRequest.getClientId(), tokenRequest.getClientSecret(),
                        tokenRequest.getGrantType(), scopes, (String) tokenRequest.getRequestParam(APIConstants
                                .OAuthConstants.SUBJECT_TOKEN), APIConstants.OAuthConstants.JWT_TOKEN_TYPE);
            } else {
                tokenResponse = authClient.generate(authToken, GRANT_TYPE_VALUE, scopes);
            }

        } catch (KeyManagerClientException e) {
            throw new APIManagementException("Error occurred while calling token endpoint - " + e.getReason(), e);
        }

        tokenInfo = new AccessTokenInfo();
        if (StringUtils.isNotEmpty(tokenResponse.getScope())) {
            tokenInfo.setScope(tokenResponse.getScope().split(" "));
        } else {
            tokenInfo.setScope(new String[0]);
        }
        tokenInfo.setAccessToken(tokenResponse.getToken());
        tokenInfo.setValidityPeriod(tokenResponse.getExpiry());

        return tokenInfo;
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest tokenRequest) throws APIManagementException {
        return null; // Implementation is not applicable.
    }

    /* Copied from AMDefaultKeyManagerImpl */
    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        try {
            IntrospectInfo introspectInfo = introspectionClient.introspect(accessToken);
            tokenInfo.setAccessToken(accessToken);
            boolean isActive = introspectInfo.isActive();
            if (!isActive || WSO2IS7KeyManagerConstants.REFRESH_TOKEN_TYPE.equalsIgnoreCase(
                    introspectInfo.getTokenType())) {
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
                return tokenInfo;
            }
            tokenInfo.setTokenValid(true);
            if (introspectInfo.getIat() > 0 && introspectInfo.getExpiry() > 0) {
                if (introspectInfo.getExpiry() != Long.MAX_VALUE) {
                    long validityPeriod = introspectInfo.getExpiry() - introspectInfo.getIat();
                    tokenInfo.setValidityPeriod(validityPeriod * 1000L);
                } else {
                    tokenInfo.setValidityPeriod(Long.MAX_VALUE);
                }
                tokenInfo.setIssuedTime(introspectInfo.getIat() * 1000L);
            }
            if (StringUtils.isNotEmpty(introspectInfo.getScope())) {
                String[] scopes = introspectInfo.getScope().split(" ");
                tokenInfo.setScope(scopes);
            }
            tokenInfo.setConsumerKey(introspectInfo.getClientId());
            String username = introspectInfo.getUsername();
            if (!StringUtils.isEmpty(username)) {
                tokenInfo.setEndUserName(username);
            }

            String authorizedUserType = introspectInfo.getAut();
            if (!StringUtils.isEmpty(authorizedUserType) && StringUtils.equalsIgnoreCase(authorizedUserType,
                    APIConstants.ACCESS_TOKEN_USER_TYPE_APPLICATION)) {
                tokenInfo.setApplicationToken(true);
            }
            return tokenInfo;
        } catch (KeyManagerClientException e) {
            throw new APIManagementException("Error occurred in token introspection!", e);
        }
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {

        return configuration;
    }

    /**
     * Copied from AMDefaultKeyManagerImpl. WSO2IS7ClientInfo is used instead of ClientInfo.
     * This method will create a new record at CLIENT_INFO table by given OauthAppRequest.
     *
     * @param appInfoRequest oAuth application properties will contain in this object
     * @return OAuthApplicationInfo with created oAuth application details.
     * @throws org.wso2.carbon.apimgt.api.APIManagementException    Failure to obtain application information,
     *                                                              or mismatching consumer key and secret.
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest appInfoRequest)
            throws APIManagementException {

        //initiate OAuthApplicationInfo
        OAuthApplicationInfo oAuthApplicationInfo = appInfoRequest.getOAuthApplicationInfo();

        String consumerKey = oAuthApplicationInfo.getClientId();
        String tokenScope = (String) oAuthApplicationInfo.getParameter("tokenScope");
        String[] tokenScopes = new String[1];
        tokenScopes[0] = tokenScope;
        String clientSecret = (String) oAuthApplicationInfo.getParameter("client_secret");
        //for the first time we set default time period.
        oAuthApplicationInfo.addParameter(ApplicationConstants.VALIDITY_PERIOD,
                getConfigurationParamValue(APIConstants.IDENTITY_OAUTH2_FIELD_VALIDITY_PERIOD));

        //check whether given consumer key and secret match or not. If it does not match throw an exception.
        WSO2IS7ClientInfo clientInfo;
        try {
            clientInfo = wso2IS7DCRClient.getApplication(consumerKey);
            buildDTOFromClientInfo(clientInfo, oAuthApplicationInfo);
        } catch (KeyManagerClientException e) {
            handleException("Some thing went wrong while getting OAuth application for given consumer key " +
                    oAuthApplicationInfo.getClientId(), e);
        }

        if (!clientSecret.equals(oAuthApplicationInfo.getClientSecret())) {
            throw new APIManagementException("The secret key is wrong for the given consumer key " + consumerKey);
        }
        oAuthApplicationInfo.addParameter("tokenScope", tokenScopes);
        oAuthApplicationInfo.setIsSaasApplication(false);

        if (log.isDebugEnabled()) {
            log.debug("Creating semi-manual application for consumer id  :  " + oAuthApplicationInfo.getClientId());
        }

        return oAuthApplicationInfo;
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * Builds an OAuthApplicationInfo object using the ClientInfo response
     *
     * @param appResponse          ClientInfo response object
     * @param oAuthApplicationInfo original OAuthApplicationInfo object
     * @return OAuthApplicationInfo object with response information added
     */
    private OAuthApplicationInfo buildDTOFromClientInfo(WSO2IS7ClientInfo appResponse,
                                                        OAuthApplicationInfo oAuthApplicationInfo) {

        oAuthApplicationInfo.setClientName(appResponse.getClientName());
        oAuthApplicationInfo.setClientId(appResponse.getClientId());
        if (appResponse.getRedirectUris() != null) {
            oAuthApplicationInfo.setCallBackURL(String.join(",", appResponse.getRedirectUris()));
            oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_REDIRECT_URIS,
                    String.join(",", appResponse.getRedirectUris()));
        }
        oAuthApplicationInfo.setClientSecret(appResponse.getClientSecret());
        if (appResponse.getGrantTypes() != null) {
            oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_GRANT,
                    String.join(" ", appResponse.getGrantTypes()));
        } else if (oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT) instanceof String) {
            oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_GRANT, ((String) oAuthApplicationInfo.
                    getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT)).replace(",", " "));
        }
        oAuthApplicationInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME, appResponse.getClientName());
        Map<String, Object> additionalProperties = new HashMap<>();
        additionalProperties.put(WSO2IS7KeyManagerConstants.APPLICATION_TOKEN_LIFETIME,
                appResponse.getApplicationTokenLifetime());
        additionalProperties.put(WSO2IS7KeyManagerConstants.USER_TOKEN_LIFETIME,
                appResponse.getUserTokenLifetime());
        additionalProperties.put(WSO2IS7KeyManagerConstants.REFRESH_TOKEN_LIFETIME,
                appResponse.getRefreshTokenLifetime());
        additionalProperties.put(WSO2IS7KeyManagerConstants.ID_TOKEN_LIFETIME, appResponse.getIdTokenLifetime());
        additionalProperties.put(WSO2IS7KeyManagerConstants.PKCE_MANDATORY, appResponse.isPkceMandatory());
        additionalProperties.put(WSO2IS7KeyManagerConstants.PKCE_SUPPORT_PLAIN, appResponse.isPkceSupportPlain());
        additionalProperties.put(WSO2IS7KeyManagerConstants.PUBLIC_CLIENT,
                appResponse.isExtPublicClient());

        oAuthApplicationInfo.addParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES, additionalProperties);
        return oAuthApplicationInfo;
    }

    private String getTenantWideCertificateValue(Object certificateObject) {
        if (certificateObject instanceof Map) {
            Map<String, String> certificateMap = (Map<String, String>) certificateObject;
            Object value = certificateMap.get("value");
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }

    private String getTenantCertAlias(String keyManagerName, String keyManagerTenantDomain) {
        return "tenant_wide_" + keyManagerName + "_"
                + getTenantIdFromTenantDomain(keyManagerTenantDomain);
    }

    private KeyStore getTrustStore() throws APIManagementException {
        ServerConfiguration serverConfig = CarbonUtils.getServerConfiguration();
        String trustStorePath = serverConfig.getFirstProperty(TRUST_STORE_LOCATION);
        String trustStorePassword = serverConfig.getFirstProperty(TRUST_STORE_PASSWORD);
        String keyStoreType = serverConfig.getFirstProperty(KEY_STORE_TYPE);

        // Load truststore (server CA cert)
        KeyStore trustStore = null;

        try (FileInputStream trustStoreFile = new FileInputStream(trustStorePath)) {
            trustStore = KeyStore.getInstance(keyStoreType);
            trustStore.load(trustStoreFile, trustStorePassword.toCharArray());
            return trustStore;
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            throw new APIManagementException(e);
        }
    }

    private void addCertificateInTrustStore(KeyStore trustStore, String base64Cert, String alias)
            throws APIManagementException {
        boolean isCertExists = false;
        boolean expired = false;
        ServerConfiguration serverConfig = CarbonUtils.getServerConfiguration();
        String trustStorePath = serverConfig.getFirstProperty(TRUST_STORE_LOCATION);
        String trustStorePassword = serverConfig.getFirstProperty(TRUST_STORE_PASSWORD);
        try {
            byte[] cert =
                    (org.apache.commons.codec.binary.Base64.decodeBase64(base64Cert.getBytes(StandardCharsets.UTF_8)));
            try (InputStream serverCert = new ByteArrayInputStream(cert)) {
                if (serverCert.available() == 0) {
                    log.error("Certificate is empty for the provided alias " + alias);
                    throw new APIManagementException("Certificate is empty for the provided alias " + alias);
                }
                //Read the client-truststore.jks into a KeyStore.
                synchronized (this) {
                    File trustStoreFile = new File(trustStorePath);
                    try (InputStream localTrustStoreStream = new FileInputStream(trustStoreFile)) {
                        TrustStoreUtils.loadCerts(trustStore, trustStorePath, trustStorePassword.toCharArray());
                        CertificateFactory cf = CertificateFactory.getInstance(certificateType);
                        while (serverCert.available() > 0) {
                            Certificate certificate = cf.generateCertificate(serverCert);
                            //Check whether the Alias exists in the trust store.
                            if (trustStore.containsAlias(alias)) {
                                isCertExists = true;
                            } else {
                                /*
                                 * If alias is not exists, check whether the certificate is expired or not. If expired
                                 * set the
                                 * expired flag.
                                 * */
                                X509Certificate x509Certificate = (X509Certificate) certificate;
                                if (x509Certificate.getNotAfter().getTime() <= System.currentTimeMillis()) {
                                    expired = true;
                                    if (log.isDebugEnabled()) {
                                        log.debug("Provided certificate is expired.");
                                    }
                                } else {
                                    //If not expired add the certificate to trust store.
                                    trustStore.setCertificateEntry(alias, certificate);
                                }
                            }
                        }
                        if (expired) {
                            throw new APIManagementException("Provided certificate is expired.");
                        } else if (isCertExists) {
                            throw new APIManagementException("Provided certificate already exists in the trust store" +
                                    " with alias: " + alias);
                        } else {
                            log.info("Successfully added the certificate with alias: " +
                                    alias + " to the trust store.");
                        }
                    }
                }
            }
        } catch (CertificateException e) {
            log.error("Error loading certificate.", e);
            throw new APIManagementException("Error loading certificate.", e);
        } catch (FileNotFoundException e) {
            log.error("Error reading/ writing to the certificate file.", e);
            throw new APIManagementException("Error reading/ writing to the certificate file.", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("Could not find the algorithm to load the certificate.", e);
            throw new APIManagementException("Could not find the algorithm to load the certificate.", e);
        } catch (UnsupportedEncodingException e) {
            log.error("Error retrieving certificate from String", e);
            throw new APIManagementException("Error retrieving certificate from String", e);
        } catch (KeyStoreException e) {
            log.error("Error reading certificate contents.", e);
            throw new APIManagementException("Error reading certificate contents.", e);
        } catch (IOException e) {
            log.error("Error in loading the certificate.", e);
            throw new APIManagementException("Error in loading the certificate.", e);
        }
    }

    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {

        this.configuration = configuration;

        String keyManagerServiceUrl = (String) configuration.getParameter(APIConstants.AUTHSERVER_URL);

        String dcrEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT) != null) {
            dcrEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT);
        } else {
            dcrEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim()).concat
                            (APIConstants.KeyManager.KEY_MANAGER_OPERATIONS_DCR_ENDPOINT);
        }

        String tokenEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT) != null) {
            tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
        } else {
            tokenEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0].concat(
                    "/oauth2/token");
        }

        addKeyManagerConfigsAsSystemProperties(tokenEndpoint);

        String introspectionEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT) != null) {
            introspectionEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT);
        } else {
            introspectionEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim()).concat("/oauth2/introspect");
        }

        String userInfoEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.USERINFO_ENDPOINT) != null) {
            userInfoEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.USERINFO_ENDPOINT);
        } else {
            userInfoEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim()).concat
                            (APIConstants.KeyManager.KEY_MANAGER_OPERATIONS_USERINFO_ENDPOINT);
        }

        String schemasEndpoint = null;
        if (StringUtils.lowerCase(userInfoEndpoint).endsWith("/me")) {
            schemasEndpoint = userInfoEndpoint.replaceAll("(?i)/me$", "/Schemas");
        }

        String apiResourceManagementEndpoint;
        if (configuration.getParameter(API_RESOURCE_MANAGEMENT_ENDPOINT) != null) {
            apiResourceManagementEndpoint = (String) configuration.getParameter(API_RESOURCE_MANAGEMENT_ENDPOINT);
        } else {
            apiResourceManagementEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim()).concat("/api/server/v1/api-resources");
        }

        String rolesEndpoint;
        if (configuration.getParameter(IS7_ROLES_ENDPOINT) != null) {
            rolesEndpoint = (String) configuration.getParameter(IS7_ROLES_ENDPOINT);
        } else {
            rolesEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim()).concat("/scim2/v2/Roles");
        }

        if (configuration.getParameter(ENABLE_ROLES_CREATION) instanceof Boolean) {
            enableRoleCreation = (Boolean) configuration.getParameter(ENABLE_ROLES_CREATION);
        }

        if ((WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS).equals(configuration.getConfiguration()
                .get(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.AUTHENTICATION))) {
            KeyStore trustStore = getTrustStore();
            // if MTLS is selected and tenant wide cert is provided, load that cert into trust store providing an alias
            if (WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.TENANTWIDE_CERTIFICATE
                    .equals(configuration.getParameter(
                            WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.MTLS_OPTIONS))) {
                addCertificateInTrustStore(trustStore, getTenantWideCertificateValue(configuration
                                .getParameter("certificates")),
                        getTenantCertAlias(configuration.getName(), configuration.getTenantDomain()));
            }
            String identityUser = (String) configuration.getConfiguration()
                    .get(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.IDENTITY_USER);
            wso2IS7DCRClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(getMutualTLSHttpClient(trustStore)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .errorDecoder(new KMClientErrorDecoder())
                    .requestInterceptor(template -> template.header(WSO2_IDENTITY_USER_HEADER, identityUser))
                    .target(WSO2IS7DCRClient.class, dcrEndpoint);

            introspectionClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(getMutualTLSHttpClient(trustStore)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(template -> template.header(WSO2_IDENTITY_USER_HEADER, identityUser))
                    .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                    .errorDecoder(new KMClientErrorDecoder())
                    .encoder(new FormEncoder())
                    .target(IntrospectionClient.class, introspectionEndpoint);

            wso2IS7APIResourceManagementClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(getMutualTLSHttpClient(trustStore)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(template -> template.header(WSO2_IDENTITY_USER_HEADER, identityUser))
                    .errorDecoder(new KMClientErrorDecoder())
                    .target(WSO2IS7APIResourceManagementClient.class, apiResourceManagementEndpoint);

            wso2IS7SCIMRolesClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(getMutualTLSHttpClient(trustStore)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(template -> template.header(WSO2_IDENTITY_USER_HEADER, identityUser))
                    .errorDecoder(new KMClientErrorDecoder())
                    .target(WSO2IS7SCIMRolesClient.class, rolesEndpoint);
        } else {
            String username = (String) configuration
                    .getParameter(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.USERNAME);
            String password = (String) configuration
                    .getParameter(WSO2IS7KeyManagerConstants.ConnectorConfigurationConstants.PASSWORD);
            wso2IS7DCRClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(dcrEndpoint)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(new BasicAuthRequestInterceptor(username, password))
                    .errorDecoder(new KMClientErrorDecoder())
                    .target(WSO2IS7DCRClient.class, dcrEndpoint);

            introspectionClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(introspectionEndpoint)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(new BasicAuthRequestInterceptor(username, password))
                    .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                    .errorDecoder(new KMClientErrorDecoder())
                    .encoder(new FormEncoder())
                    .target(IntrospectionClient.class, introspectionEndpoint);

            wso2IS7SCIMSchemasClient = schemasEndpoint != null ? Feign.builder()
                    .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(schemasEndpoint)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .errorDecoder(new KMClientErrorDecoder())
                    .target(WSO2IS7SCIMSchemasClient.class, schemasEndpoint) : null;

            wso2IS7APIResourceManagementClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(apiResourceManagementEndpoint)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(new BasicAuthRequestInterceptor(username, password))
                    .errorDecoder(new KMClientErrorDecoder())
                    .target(WSO2IS7APIResourceManagementClient.class, apiResourceManagementEndpoint);

            wso2IS7SCIMRolesClient = Feign.builder()
                    .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(rolesEndpoint)))
                    .encoder(new GsonEncoder())
                    .decoder(new GsonDecoder())
                    .logger(new Slf4jLogger())
                    .requestInterceptor(new BasicAuthRequestInterceptor(username, password))
                    .errorDecoder(new KMClientErrorDecoder())
                    .target(WSO2IS7SCIMRolesClient.class, rolesEndpoint);
        }
        authClient = Feign.builder()
                .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(tokenEndpoint)))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .errorDecoder(new KMClientErrorDecoder())
                .encoder(new FormEncoder())
                .target(AuthClient.class, tokenEndpoint);

        wso2IS7SCIMMeClient = Feign.builder()
                .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(userInfoEndpoint)))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .errorDecoder(new KMClientErrorDecoder())
                .target(WSO2IS7SCIMMeClient.class, userInfoEndpoint);

        claimMappings = ClaimMappingReader.loadClaimMappings();

        if (configuration.getParameter(WSO2ISConstants.ENABLE_SCHEMA_CACHE) instanceof Boolean && Boolean.parseBoolean
                (configuration.getParameter(WSO2ISConstants.ENABLE_SCHEMA_CACHE).toString())) {
            boolean isTenantFlowStarted = false;
            try {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
                isTenantFlowStarted = true;
                APIUtil.getCache(APIConstants.API_MANAGER_CACHE_MANAGER, WSO2ISConstants.USER_SCHEMA_CACHE,
                        USER_SCHEMA_CACHE_EXPIRY, USER_SCHEMA_CACHE_EXPIRY);
            } catch (Exception e) {
                throw new APIManagementException("Error occurred while initializing WSO2 IS7 Key Manager: User " +
                        "Schema Cache initialization failed.", e);
            } finally {
                if (isTenantFlowStarted) {
                    PrivilegedCarbonContext.endTenantFlow();
                }
            }
        }
    }

    public static HttpClient getMutualTLSHttpClient(KeyStore trustStore) throws APIManagementException {

        ServerConfiguration serverConfig = CarbonUtils.getServerConfiguration();
        String trustStorePath = serverConfig.getFirstProperty(TRUST_STORE_LOCATION);
        String trustStorePassword = serverConfig.getFirstProperty(TRUST_STORE_PASSWORD);
        System.setProperty(JAVAX_NET_SSL_TRUST_STORE, trustStorePath);
        System.setProperty(JAVAX_NET_SSL_TRUST_STORE_PASSWORD, trustStorePassword);

        String keyStorePath = serverConfig.getFirstProperty(KEY_STORE_LOCATION);
        String keyStoreType = serverConfig.getFirstProperty(KEY_STORE_TYPE);
        String keyStorePassword = serverConfig.getFirstProperty(KEY_STORE_PASSWORD);

        // Load keystore (client certificate)
        KeyStore keyStore = null;
        SSLContext sslContext;
        try {
            keyStore = KeyStore.getInstance(keyStoreType);

            try (FileInputStream keyStoreFile = new FileInputStream(keyStorePath)) {
                keyStore.load(keyStoreFile, keyStorePassword.toCharArray());
            }

            // Create key managers
            KeyManagerFactory keyManagerFactory = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());

            // Create trust managers
            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Create SSL context with both managers
            sslContext = SSLContext.getInstance(TLS);
            sslContext.init(keyManagerFactory.getKeyManagers(),
                    trustManagerFactory.getTrustManagers(), new SecureRandom());

        } catch (UnrecoverableKeyException | IOException | CertificateException | KeyStoreException |
                 KeyManagementException | NoSuchAlgorithmException e) {
            log.error("Error while initializing SSL context for mutual TLS", e);
            throw new APIManagementException(e);
        }

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext,
                new String[]{TLS_V1_2, TLS_V1_3},
                null,
                new DefaultHostnameVerifier()
        );


        return HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .build();
    }


    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {

        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {

        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {

        return false;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String consumerKey) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) throws APIManagementException {

        return new HashSet<>();
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String consumerKey) throws APIManagementException {

        return new AccessTokenInfo();
    }

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String apiIdsString)
            throws APIManagementException {

        return null;
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * This method will be used to register a Scope in the authorization server.
     *
     * @param scope Scope to register
     * @throws APIManagementException if there is an error while registering a new scope.
     */
    @Override
    public void registerScope(Scope scope) throws APIManagementException {

        String wso2IS7APIResourceId = getWSO2IS7APIResourceId();
        registerWSO2IS7Scopes(wso2IS7APIResourceId, Collections.singleton(scope));
    }

    /**
     * Gets the ID of the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER}.
     * @return                          ID of the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER} if exists, else null.
     * @throws APIManagementException   Failed to get the ID of the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER}.
     */
    private String getWSO2IS7APIResourceId() throws APIManagementException {

        try {
            String filter = "identifier eq " + DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER;
            JsonObject apiResourcesResponse = wso2IS7APIResourceManagementClient
                    .getAPIResources(Collections.singletonMap("filter", filter));
            JsonArray apiResources = apiResourcesResponse.getAsJsonArray("apiResources");
            if (apiResources != null && !apiResources.isJsonNull() && apiResources.size() > 0) {
                return apiResources.get(0).getAsJsonObject().get("id").getAsString();
            }
        } catch (KeyManagerClientException e) {
            handleException("Failed to get the ID of WSO2 IS7 API Resource: " + DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER, e);
        }
        return null;
    }

    /**
     * Registers WSO2 IS7 Scopes in the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER} API resource of WSO2 IS7,
     * for the provided scopes.
     * @param wso2IS7APIResourceId      ID of the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER}.
     * @param newScopes                 Scopes to be added.
     * @throws APIManagementException   Failed to register scopes in WSO2 IS7.
     */
    private void registerWSO2IS7Scopes(String wso2IS7APIResourceId, Set<Scope> newScopes)
            throws APIManagementException {

        List<WSO2IS7APIResourceScopeInfo> nonExistingWSO2IS7Scopes;
        if (wso2IS7APIResourceId != null) {
            try {
                Set<String> existingScopeNames = getExistingWSO2IS7ScopeNames(wso2IS7APIResourceId);
                nonExistingWSO2IS7Scopes = getNonExistingWSO2IS7Scopes(newScopes, existingScopeNames);
                addScopesToWSO2IS7APIResource(wso2IS7APIResourceId, nonExistingWSO2IS7Scopes);
            } catch (KeyManagerClientException e) {
                handleException("Failed to add scopes to WSO2 IS7 API Resource: " +
                        DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER, e);
            }
        } else {
            try {
                nonExistingWSO2IS7Scopes = getNonExistingWSO2IS7Scopes(newScopes, Collections.emptySet());
                createWSO2IS7APIResource(nonExistingWSO2IS7Scopes);
            } catch (KeyManagerClientException e) {
                handleException("Failed to create WSO2 IS7 API Resource: " + DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER +
                        " with scopes", e);
            }
        }
        createWSO2IS7RoleToScopeBindings(newScopes);
    }

    /**
     * Gets the list of existing WSO2 IS7 scope names of the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER}.
     * @param wso2IS7APIResourceId          ID of the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER}.
     * @return                              Set of existing WSO2 IS7 scope names.
     * @throws KeyManagerClientException    Failed to get the existing WSO2 IS7 scope names.
     */
    private Set<String> getExistingWSO2IS7ScopeNames(String wso2IS7APIResourceId) throws KeyManagerClientException {

        JsonArray existingScopes = wso2IS7APIResourceManagementClient.getAPIResourceScopes(wso2IS7APIResourceId);
        Set<String> existingScopeNames = new HashSet<>();
        for (JsonElement scope : existingScopes) {
            existingScopeNames.add(scope.getAsJsonObject().get("name").getAsString());
        }
        return existingScopeNames;
    }

    /**
     * Checks the provided set of new WSO2 IS7 scopes against the provided set of existing WSO2 IS7 scope names,
     * and returns the list of non-existing WSO2 IS7 scopes.
     * @param newLocalScopes        Set of new WSO2 IS7 scopes that have been created.
     * @param existingScopeNames    Set of existing WSO2 IS7 scope names.
     * @return                      List of non-existing WSO2 IS7 scopes.
     */
    private List<WSO2IS7APIResourceScopeInfo> getNonExistingWSO2IS7Scopes(Set<Scope> newLocalScopes,
                                                                          Set<String> existingScopeNames) {

        List<WSO2IS7APIResourceScopeInfo> wso2IS7ScopesToAdd = new ArrayList<>();
        for (Scope scope : newLocalScopes) {
            if (!existingScopeNames.contains(scope.getName())) {
                wso2IS7ScopesToAdd.add(new WSO2IS7APIResourceScopeInfo(scope.getKey(), scope.getName(),
                        scope.getDescription()));
            }
        }
        return wso2IS7ScopesToAdd;
    }

    /**
     * Adds the provided list of WSO2 IS7 scopes to the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER} API resource.
     * @param wso2IS7APIResourceId          ID of the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER}.
     * @param scopes                        List of WSO2 IS7 scopes to be added.
     * @throws KeyManagerClientException    Failed to add scopes to the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER}.
     */
    private void addScopesToWSO2IS7APIResource(String wso2IS7APIResourceId, List<WSO2IS7APIResourceScopeInfo> scopes)
            throws KeyManagerClientException {

        if (scopes.isEmpty()) {
            return;
        }
        WSO2IS7APIResourceInfo.AddedScopesInfo addedScopes = new WSO2IS7APIResourceInfo.AddedScopesInfo();
        addedScopes.setAddedScopes(scopes);
        wso2IS7APIResourceManagementClient.patchAPIResource(wso2IS7APIResourceId, addedScopes);
    }

    /**
     * Creates the {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER} API resource with the provided list of WSO2 IS7 scopes.
     * @param scopes                        List of WSO2 IS7 scopes to be added.
     * @return                              Created {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER} API resource.
     * @throws KeyManagerClientException    Failed to create {@link #DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER} API resource.
     */
    private WSO2IS7APIResourceInfo createWSO2IS7APIResource(List<WSO2IS7APIResourceScopeInfo> scopes)
            throws KeyManagerClientException {

        WSO2IS7APIResourceInfo wso2IS7APIResourceInfo = new WSO2IS7APIResourceInfo();
        wso2IS7APIResourceInfo.setIdentifier(DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER);
        wso2IS7APIResourceInfo.setName(DEFAULT_OAUTH_2_RESOURCE_NAME);
        wso2IS7APIResourceInfo.setDescription(DEFAULT_OAUTH_2_RESOURCE_DESCRIPTION);
        wso2IS7APIResourceInfo.setRequiresAuthorization(true);
        wso2IS7APIResourceInfo.setScopes(scopes);
        return wso2IS7APIResourceManagementClient.createAPIResource(wso2IS7APIResourceInfo);
    }

    /**
     * Adds WSO2 IS7 role-to-scope bindings for the provided set of scopes.
     * @param scopes                    Set of scopes to add role-to-scope bindings.
     * @throws APIManagementException   Failed to add role-to-scope bindings.
     */
    private void createWSO2IS7RoleToScopeBindings(Set<Scope> scopes) throws APIManagementException {

        for (Scope scope : scopes) {
            List<String> roles = getRoles(scope);
            for (String apimRole : roles) {
                String is7RoleName = getWSO2IS7RoleName(apimRole);
                try {
                    String roleId = getWSO2IS7RoleId(is7RoleName);
                    if (roleId != null) {
                        // Add this scope(permission) to existing role
                        addScopeToWSO2IS7Role(scope, roleId);
                    } else if (enableRoleCreation) {
                        // Create new role with this scope(permission)
                        Map<String, String> wso2IS7Scope = new HashMap<>();
                        wso2IS7Scope.put("value", scope.getKey());
                        wso2IS7Scope.put("display", scope.getName());
                        createWSO2IS7Role(is7RoleName, Collections.singletonList(wso2IS7Scope));
                    }
                } catch (KeyManagerClientException e) {
                    handleException("Failed to get the role ID for role: " + apimRole, e);
                }
            }
        }
    }

    /**
     * Gets the ID of the WSO2 IS7 role that has the given display name.
     * @param roleDisplayName               Display name of the WSO2 IS7 role.
     * @return                              ID of the WSO2 IS7 role if exists, else null.
     * @throws KeyManagerClientException    Failed to get the ID of the WSO2 IS7 role.
     */
    private String getWSO2IS7RoleId(String roleDisplayName) throws KeyManagerClientException {

        String filter = "displayName eq " + roleDisplayName;
        JsonArray roles = searchRoles(filter);
        if (roles != null && !roles.isJsonNull() && roles.size() > 0) {
            return roles.get(0).getAsJsonObject().get("id").getAsString();
        }
        return null;
    }

    /**
     * Adds the given scope to the WSO2 IS7 role with the given ID.
     * @param scope                     Scope to add.
     * @param roleId                    ID of the WSO2 IS7 role.
     * @throws APIManagementException   Failed to add the scope to the role.
     */
    private void addScopeToWSO2IS7Role(Scope scope, String roleId) throws APIManagementException {

        try {
            WSO2IS7RoleInfo role = wso2IS7SCIMRolesClient.getRole(roleId);
            List<Map<String, String>> permissions = role.getPermissions();

            List<WSO2IS7PatchRoleOperationInfo.Permission> allPermissions = new ArrayList<>();
            for (Map<String, String> existingPermission : permissions) {
                WSO2IS7PatchRoleOperationInfo.Permission permission = new WSO2IS7PatchRoleOperationInfo.Permission();
                permission.setValue(existingPermission.get("value"));
                permission.setDisplay(existingPermission.get("display"));
                allPermissions.add(permission);
            }
            WSO2IS7PatchRoleOperationInfo.Permission addedPermission = new WSO2IS7PatchRoleOperationInfo.Permission();
            addedPermission.setValue(scope.getKey());
            addedPermission.setDisplay(scope.getName());
            allPermissions.add(addedPermission);

            updateWSO2IS7RoleWithScopes(roleId, allPermissions);
        } catch (KeyManagerClientException e) {
            handleException("Failed to add scope: " + scope.getKey() + " to the role with ID: " + roleId, e);
        }
    }

    /**
     * Updates the WSO2 IS7 role with the given ID, with the provided WSO2 IS7 scopes.
     * @param roleId                        ID of the WSO2 IS7 role.
     * @param scopes                        List of WSO2 IS7 scopes, that the WSO2 IS7 role should be updated with.
     * @throws KeyManagerClientException    Failed to update the WSO2 IS7 role.
     */
    private void updateWSO2IS7RoleWithScopes(String roleId, List<WSO2IS7PatchRoleOperationInfo.Permission> scopes)
            throws KeyManagerClientException {
        WSO2IS7PatchRoleOperationInfo.Value value = new WSO2IS7PatchRoleOperationInfo.Value();
        value.setPermissions(scopes);

        WSO2IS7PatchRoleOperationInfo.Operation replaceOperation =
                new WSO2IS7PatchRoleOperationInfo.Operation();
        replaceOperation.setOp("replace");
        replaceOperation.setValue(value);

        WSO2IS7PatchRoleOperationInfo patchOperationInfo = new WSO2IS7PatchRoleOperationInfo();
        patchOperationInfo.setOperations(Collections.singletonList(replaceOperation));
        wso2IS7SCIMRolesClient.patchRole(roleId, patchOperationInfo);
    }

    /**
     * Creates a new WSO2 IS7 role with the given display name and scopes.
     * @param displayName               Display name of the WSO2 IS7 role.
     * @param scopes                    List of scopes to be added to the role.
     * @throws APIManagementException   Failed to create the WSO2 IS7 role.
     */
    private void createWSO2IS7Role(String displayName, List<Map<String, String>> scopes) throws APIManagementException {

        WSO2IS7RoleInfo role = new WSO2IS7RoleInfo();
        role.setDisplayName(displayName);
        role.setPermissions(scopes);
        try {
            wso2IS7SCIMRolesClient.createRole(role);
        } catch (KeyManagerClientException e) {
            handleException("Failed to create role: " + displayName, e);
        }
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * This method will be used to retrieve details of a Scope in the authorization server.
     *
     * @param name Scope Name to retrieve
     * @return Scope object
     * @throws APIManagementException if an error while retrieving scope
     */
    @Override
    public Scope getScopeByName(String name) throws APIManagementException {

        String wso2IS7APIResourceId = getWSO2IS7APIResourceId();
        if (wso2IS7APIResourceId != null) {
            try {
                JsonArray scopes = wso2IS7APIResourceManagementClient.getAPIResourceScopes(wso2IS7APIResourceId);
                JsonArray allRoles = searchRoles(null);
                for (JsonElement scope : scopes) {
                    JsonObject scopeJsonObject = scope.getAsJsonObject();
                    String scopeName = scopeJsonObject.get("name").getAsString();
                    if (name.equals(scopeName)) {
                        String scopeDisplayName = scopeJsonObject.get("displayName").getAsString();

                        Scope foundScope = new Scope();
                        foundScope.setKey(scopeName);
                        foundScope.setName(scopeDisplayName);
                        foundScope.setDescription(scopeJsonObject.get("description") != null ?
                                scopeJsonObject.get("description").getAsString() :
                                StringUtils.EMPTY);
                        List<String> is7ScopeRoles = getWSO2IS7RolesHavingScope(scopeName, allRoles);
                        List<String> apimRoles = getAPIMRolesFromIS7Roles(is7ScopeRoles);
                        foundScope.setRoles(String.join(",", apimRoles));
                        return foundScope;
                    }
                }
            } catch (KeyManagerClientException e) {
                handleException("Error occurred while retrieving scope by name: " + name, e);
            }
        }
        return null;
    }

    /**
     * Searches for WSO2 IS7 roles with the given filter.
     * @param filter                        Filter to search for roles.
     * @return                              Response with the list of roles.
     * @throws KeyManagerClientException    Failed to search for roles.
     */
    private JsonArray searchRoles(String filter) throws KeyManagerClientException {

        JsonObject payload = new JsonObject();
        JsonArray schemas = new JsonArray();
        schemas.add(SEARCH_REQUEST_SCHEMA);
        payload.add("schemas", schemas);
        if (filter != null) {
            payload.addProperty("filter", filter);
        }
        JsonObject rolesResponse = wso2IS7SCIMRolesClient.searchRoles(payload);
        return rolesResponse.getAsJsonArray("Resources");
    }

    /**
     * Gets the list of WSO2 IS7 role display names - that have the given WSO2 IS7 scope, from the given roles.
     * @param scopeName Name of the WSO2 IS7 scope.
     * @param roles     All roles.
     * @return          List of role display names that have the given WSO2 IS7 scope.
     */
    private List<String> getWSO2IS7RolesHavingScope(String scopeName, JsonArray roles) {
        List<String> scopeRoles = new ArrayList<>();
        if (roles != null && !roles.isJsonNull()) {
            for (JsonElement role : roles) {
                JsonArray permissions = role.getAsJsonObject().getAsJsonArray("permissions");
                if (permissions != null && !permissions.isJsonNull()) {
                    for (JsonElement permission : permissions) {
                        if (scopeName.equals(permission.getAsJsonObject().get("value").getAsString())) {
                            // This role has the given scope(permission)
                            scopeRoles.add(role.getAsJsonObject().get("displayName").getAsString());
                            break;
                        }
                    }
                }
            }
        }
        return scopeRoles;
    }
    /**
     * Converts a list of WSO2 IS7 roles to API Manager roles.
     * If a role starts with "system_primary_", it removes the prefix.
     * Otherwise, it prepends "Internal/" to the role name.
     *
     * @param is7Roles List of WSO2 IS7 roles.
     * @return List of API Manager roles.
     */
    private List<String> getAPIMRolesFromIS7Roles(List<String> is7Roles) {
        return is7Roles.stream()
                .map(roleName -> roleName.startsWith("system_primary_")
                        ? roleName.replaceFirst("^system_primary_", "")
                        : "Internal/" + roleName)
                .collect(Collectors.toList());
    }
    /**
     * Copied from AMDefaultKeyManagerImpl.
     * This method will be used to retrieve all the scopes available in the authorization server for the given tenant
     * domain.
     *
     * @return Mapping of Scope object to scope key
     * @throws APIManagementException if an error occurs while getting scopes list
     */
    @Override
    public Map<String, Scope> getAllScopes() throws APIManagementException {

        String wso2IS7APIResourceId = getWSO2IS7APIResourceId();
        Map<String, Scope> scopes = new HashMap<>();
        if (wso2IS7APIResourceId == null) {
            return scopes;
        }
        try {
            JsonArray scopesResponse = wso2IS7APIResourceManagementClient.getAPIResourceScopes(wso2IS7APIResourceId);
            JsonArray allRoles = searchRoles(null);

            for (JsonElement scopeJsonElement : scopesResponse) {
                String scopeName = scopeJsonElement.getAsJsonObject().get("name").getAsString();
                Scope scope = new Scope();
                scope.setKey(scopeName);
                scope.setName(scopeJsonElement.getAsJsonObject().get("displayName").getAsString());
                scope.setDescription(scopeJsonElement.getAsJsonObject().get("description").getAsString());
                scope.setRoles(String.join(",", getWSO2IS7RolesHavingScope(scopeName, allRoles)));
                scopes.put(scopeName, scope);
            }
        } catch (KeyManagerClientException e) {
            handleException("Error while retrieving scopes", e);
        }
        return scopes;
    }

    @Override
    public void attachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

        // Nothing to do here.
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * This method will be used to update the local scopes and resource to scope attachments of an API in the
     * authorization server.
     *
     * @param api               API
     * @param oldLocalScopeKeys Old local scopes of the API before update (excluding the versioned local scopes
     * @param newLocalScopes    New local scopes of the API after update
     * @param oldURITemplates   Old URI templates of the API before update
     * @param newURITemplates   New URI templates of the API after update
     * @throws APIManagementException if fails to update resources scopes
     */
    @Override
    public void updateResourceScopes(API api, Set<String> oldLocalScopeKeys, Set<Scope> newLocalScopes,
                                     Set<URITemplate> oldURITemplates, Set<URITemplate> newURITemplates)
            throws APIManagementException {

        String wso2IS7APIResourceId = getWSO2IS7APIResourceId();
        // Remove the old local scopes
        if (wso2IS7APIResourceId != null) {
            for (String oldScope : oldLocalScopeKeys) {
                try {
                    wso2IS7APIResourceManagementClient.deleteScopeFromAPIResource(wso2IS7APIResourceId, oldScope);
                } catch (KeyManagerClientException e) {
                    handleException("Failed to delete scope: " + oldScope + " from WSO2 IS7 API Resource: " +
                            DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER, e);
                }
            }
        }
        registerWSO2IS7Scopes(wso2IS7APIResourceId, newLocalScopes);
    }

    @Override
    public void detachResourceScopes(API api, Set<URITemplate> uriTemplates)
            throws APIManagementException {

        // Nothing to do here.
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * This method will be used to delete a Scope in the authorization server.
     *
     * @param scopeName Scope name
     * @throws APIManagementException if an error occurs while deleting the scope
     */
    @Override
    public void deleteScope(String scopeName) throws APIManagementException {

        String wso2IS7APIResourceId = getWSO2IS7APIResourceId();
        if (wso2IS7APIResourceId != null) {
            try {
                wso2IS7APIResourceManagementClient.deleteScopeFromAPIResource(wso2IS7APIResourceId, scopeName);
            } catch (KeyManagerClientException e) {
                handleException("Failed to delete scope: " + scopeName + " from WSO2 IS7 API Resource: " +
                        DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER, e);
            }
        }
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * This method will be used to update a Scope in the authorization server.
     *
     * @param scope Scope object
     * @throws APIManagementException if an error occurs while updating the scope
     */
    @Override
    public void updateScope(Scope scope) throws APIManagementException {

        try {
            String wso2IS7APIResourceId = getWSO2IS7APIResourceId();
            if (wso2IS7APIResourceId != null) {
                WSO2IS7APIResourceScopeInfo scopeInfo = new WSO2IS7APIResourceScopeInfo();
                scopeInfo.setDisplayName(scope.getName());
                scopeInfo.setDescription(scope.getDescription());
                try {
                    wso2IS7APIResourceManagementClient.patchAPIResourceScope(wso2IS7APIResourceId, scope.getKey(),
                            scopeInfo);
                } catch (KeyManagerClientException e) {
                    handleException("Failed to update scope: " + scope.getName() + " in WSO2 IS7 API Resource: " +
                            DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER, e);
                }
            }
            JsonArray allIS7Roles = searchRoles(null);
            List<String> existingAPIMRoles = getAPIMRolesFromIS7Roles(
                    getWSO2IS7RolesHavingScope(scope.getKey(), allIS7Roles));

            // Add new scope-to-role bindings
            List<String> apimScopeRoles = getRoles(scope);

            List<String> apimRoleBindingsToAdd = new ArrayList<>(apimScopeRoles);
            apimRoleBindingsToAdd.removeAll(existingAPIMRoles);

            if (!apimRoleBindingsToAdd.isEmpty()) {
                Scope addableScope = new Scope();
                addableScope.setKey(scope.getKey());
                addableScope.setName(scope.getName());
                addableScope.setDescription(scope.getDescription());
                addableScope.setRoles(String.join(",", apimRoleBindingsToAdd));
                createWSO2IS7RoleToScopeBindings(Collections.singleton(addableScope));
            }

            // Remove old scope-to-role bindings
            List<String> roleBindingsToRemove = new ArrayList<>(existingAPIMRoles);
            roleBindingsToRemove.removeAll(apimScopeRoles);
            if (!roleBindingsToRemove.isEmpty()) {
                removeWSO2IS7RoleToScopeBindings(scope.getKey(), roleBindingsToRemove);
            }
        } catch (KeyManagerClientException e) {
            handleException("Failed to update scope: " + scope.getName(), e);
        }
    }

    /**
     * Removes the given WSO2 IS7 scopes from the given WSO2 IS7 roles.
     * @param scopeName                 Name of the WSO2 IS7 scope.
     * @param roles                     WSO2 IS7 Roles to remove the scope from.
     * @throws APIManagementException   Failed to remove role-to-scope bindings.
     */
    private void removeWSO2IS7RoleToScopeBindings(String scopeName, List<String> roles) throws APIManagementException {
        for (String role : roles) {
            try {
                String roleName = getWSO2IS7RoleName(role);
                String roleId = getWSO2IS7RoleId(roleName);
                if (roleId != null) {
                    WSO2IS7RoleInfo roleInfo = wso2IS7SCIMRolesClient.getRole(roleId);
                    List<Map<String, String>> existingScopes = roleInfo.getPermissions();

                    // Update the role with all the existing scopes(permissions) except the given scope(permission)
                    List<WSO2IS7PatchRoleOperationInfo.Permission> permissions = new ArrayList<>();
                    for (Map<String, String> existingScope : existingScopes) {
                        if (!scopeName.equals(existingScope.get("value"))) {
                            WSO2IS7PatchRoleOperationInfo.Permission permission =
                                    new WSO2IS7PatchRoleOperationInfo.Permission();
                            permission.setValue(existingScope.get("value"));
                            permissions.add(permission);
                        }
                    }
                    updateWSO2IS7RoleWithScopes(roleId, permissions);
                }
            } catch (KeyManagerClientException e) {
                handleException("Failed to remove role-to-scope bindings for role: " + role, e);
            }
        }
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * This method will be used to check whether the a Scope exists for the given scope name in the authorization
     * server.
     *
     * @param scopeName Scope Name
     * @return whether scope exists or not
     * @throws APIManagementException if an error occurs while checking the existence of the scope
     */
    @Override
    public boolean isScopeExists(String scopeName) throws APIManagementException {

        String wso2IS7APIResourceId = getWSO2IS7APIResourceId();
        if (wso2IS7APIResourceId == null) {
            return false;
        }

        try {
            JsonArray existingScopes = wso2IS7APIResourceManagementClient.getAPIResourceScopes(wso2IS7APIResourceId);
            for (JsonElement scope : existingScopes) {
                if (scopeName.equals(scope.getAsJsonObject().get("name").getAsString())) {
                    return true;
                }
            }
        } catch (KeyManagerClientException e) {
            handleException("Failed to get scopes from WSO2 IS7 API Resource: " +
                    DEFAULT_OAUTH_2_RESOURCE_IDENTIFIER, e);
        }
        return false;
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * This method will be used to validate the scope set provided and populate the additional parameters
     * (description and bindings) for each Scope object.
     *
     * @param scopes Scope set to validate
     * @throws APIManagementException if an error occurs while validating and populating
     */
    @Override
    public void validateScopes(Set<Scope> scopes) throws APIManagementException {

        for (Scope scope : scopes) {
            Scope sharedScope = getScopeByName(scope.getKey());
            scope.setName(sharedScope.getName());
            scope.setDescription(sharedScope.getDescription());
            scope.setRoles(sharedScope.getRoles());
        }
    }

    @Override
    public String getType() {

        return WSO2IS7KeyManagerConstants.WSO2_IS7_TYPE;
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * Return the value of the provided configuration parameter.
     *
     * @param parameter Parameter name
     * @return Parameter value
     */
    protected String getConfigurationParamValue(String parameter) {

        return (String) configuration.getParameter(parameter);
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * Check whether Token partitioning is enabled.
     *
     * @return true/false
     */
    protected boolean checkAccessTokenPartitioningEnabled() {

        return APIUtil.checkAccessTokenPartitioningEnabled();
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * Check whether user name assertion is enabled.
     *
     * @return true/false
     */
    protected boolean checkUserNameAssertionEnabled() {

        return APIUtil.checkUserNameAssertionEnabled();
    }

    /* Copied from AMDefaultKeyManagerImpl. */
    private String getTenantAwareContext() {

        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return "/t/".concat(tenantDomain);
        }
        return "";
    }

    /* Copied from AMDefaultKeyManagerImpl. */
    private void addKeyManagerConfigsAsSystemProperties(String serviceUrl) {

        URL keyManagerURL;
        try {
            keyManagerURL = new URL(serviceUrl);
            String hostname = keyManagerURL.getHost();

            int port = keyManagerURL.getPort();
            if (port == -1) {
                if (APIConstants.HTTPS_PROTOCOL.equals(keyManagerURL.getProtocol())) {
                    port = APIConstants.HTTPS_PROTOCOL_PORT;
                } else {
                    port = APIConstants.HTTP_PROTOCOL_PORT;
                }
            }
            System.setProperty(APIConstants.KEYMANAGER_PORT, String.valueOf(port));

            if (hostname.equals(System.getProperty(APIConstants.CARBON_LOCALIP))) {
                System.setProperty(APIConstants.KEYMANAGER_HOSTNAME, "localhost");
            } else {
                System.setProperty(APIConstants.KEYMANAGER_HOSTNAME, hostname);
            }
            //Since this is the server startup.Ignore the exceptions,invoked at the server startup
        } catch (MalformedURLException e) {
            log.error("Exception While resolving KeyManager Server URL or Port " + e.getMessage(), e);
        }
    }

    @Override
    public Map<String, String> getUserClaims(String username, Map<String, Object> properties)
            throws APIManagementException {

        Map<String, String> userClaims = new HashMap<>();
        if (properties.containsKey(APIConstants.KeyManager.ACCESS_TOKEN)) {
            String accessToken = properties.get(APIConstants.KeyManager.ACCESS_TOKEN).toString();
            try {
                JsonObject scimUserObjectString = wso2IS7SCIMMeClient.getMe(accessToken);
                Map<String, String> claims = AttributeMapper.getUserClaims(scimUserObjectString.toString(),
                        wso2IS7SCIMSchemasClient, accessToken, configuration, tenantDomain);
                Map<String, String> claimMappings = getClaimMappings();
                userClaims = getMappedAttributes(claims, claimMappings);
            } catch (KeyManagerClientException e) {
                throw new APIManagementException("Error while getting user info for user: " + username, e);
            }
        }
        return userClaims;
    }

    private Map<String, String> getClaimMappings() {
        Map<String, String> claimMappings = this.claimMappings;

        // Add configured claim mappings (overwrite if present).
        List<Map<String, String>> configuredClaimMappings =
                (List<Map<String, String>>) this.configuration.getParameter(CLAIM_MAPPINGS_CONFIG_PARAMETER);
        for (Map<String, String> claimMapping : configuredClaimMappings) {
            String remoteClaim = claimMapping.get(REMOTE_CLAIM);
            String localClaim = claimMapping.get(LOCAL_CLAIM);
            claimMappings.put(remoteClaim, localClaim);
        }

        return claimMappings;
    }

    private Map<String, String> getMappedAttributes(Map<String, String> claims, Map<String, String> claimMappings) {
        Map<String, String> mappedAttributes = new HashMap<>();
        for (Map.Entry<String, String> claim : claims.entrySet()) {
            String scim2Claim = claim.getKey();
            String localClaim = claimMappings.get(scim2Claim);
            if (localClaim != null) {
                mappedAttributes.put(localClaim, claim.getValue());
            }
        }
        return mappedAttributes;
    }

    @Override
    public void revokeOneTimeToken(String token, String consumerKey) {

        // Implementation is not applicable.
    }

    /* Copied from AMDefaultKeyManagerImpl. */
    @Override
    protected void validateOAuthAppCreationProperties(OAuthApplicationInfo oAuthApplicationInfo)
            throws APIManagementException {

        super.validateOAuthAppCreationProperties(oAuthApplicationInfo);

        String type = getType();
        KeyManagerConnectorConfiguration keyManagerConnectorConfiguration = ServiceReferenceHolder.getInstance()
                .getKeyManagerConnectorConfiguration(type);
        if (keyManagerConnectorConfiguration != null) {
            Object additionalProperties = oAuthApplicationInfo.getParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES);
            if (additionalProperties != null) {
                JsonObject additionalPropertiesJson = (JsonObject) new JsonParser()
                        .parse((String) additionalProperties);
                for (Map.Entry<String, JsonElement> entry : additionalPropertiesJson.entrySet()) {
                    String additionalProperty = entry.getValue().getAsString();
                    if (StringUtils.isNotBlank(additionalProperty) && !StringUtils
                            .equals(additionalProperty, APIConstants.KeyManager.NOT_APPLICABLE_VALUE)) {
                        try {
                            if (WSO2IS7KeyManagerConstants.PKCE_MANDATORY.equals(entry.getKey()) ||
                                    WSO2IS7KeyManagerConstants.PKCE_SUPPORT_PLAIN.equals(entry.getKey()) ||
                                    WSO2IS7KeyManagerConstants.PUBLIC_CLIENT.equals(entry.getKey())) {

                                if (!(additionalProperty.equalsIgnoreCase(Boolean.TRUE.toString()) ||
                                        additionalProperty.equalsIgnoreCase(Boolean.FALSE.toString()))) {
                                    String errMsg = "Application configuration values cannot have negative values.";
                                    throw new APIManagementException(errMsg, ExceptionCodes
                                            .from(ExceptionCodes.INVALID_APPLICATION_ADDITIONAL_PROPERTIES, errMsg));
                                }
                            } else {
                                Long longValue = Long.parseLong(additionalProperty);
                                if (longValue < 0) {
                                    String errMsg = "Application configuration values cannot have negative values.";
                                    throw new APIManagementException(errMsg, ExceptionCodes
                                            .from(ExceptionCodes.INVALID_APPLICATION_ADDITIONAL_PROPERTIES, errMsg));
                                }
                            }
                        } catch (NumberFormatException e) {
                            String errMsg = "Application configuration values cannot have string values.";
                            throw new APIManagementException(errMsg, ExceptionCodes
                                    .from(ExceptionCodes.INVALID_APPLICATION_ADDITIONAL_PROPERTIES, errMsg));
                        }
                    }
                }
            }
        }
    }

    /**
     * Gets the list of roles from the given scope.
     * @param scope Scope to get the roles.
     * @return      List of roles.
     */
    private List<String> getRoles(Scope scope) {

        if (StringUtils.isNotBlank(scope.getRoles()) && scope.getRoles().trim().split(",").length > 0) {
            return Arrays.asList(scope.getRoles().trim().split(","));
        }
        return Collections.emptyList();
    }
    /**
     * Retrieves the WSO2 IS7 role name based on the provided role name.
     * If role creation is disabled, the original role name is returned.
     * When role creation is enabled, the method applies specific naming conventions:
     * - Removes the "Internal/" prefix if present.
     * - Throws an exception if the role starts with "Application/".
     * - Prepends "system_primary_" to the role name if no specific prefix is found.
     *
     * @param roleName The role name to process.
     * @return The processed WSO2 IS7 role name.
     * @throws APIManagementException If the role name is invalid.
     */
    private String getWSO2IS7RoleName(String roleName) throws APIManagementException {
        if (!enableRoleCreation) {
            return roleName;
        }
        // When role creation is enabled, conventions of the WSO2 IS7 migration client are followed for roles.
        if (roleName.startsWith("Internal/")) {
            return roleName.replace("Internal/", "");
        } else if (roleName.startsWith("Application/")) {
            throw new APIManagementException("Role: " + roleName + " is invalid.");
        }
        return "system_primary_" + roleName;
    }

}
