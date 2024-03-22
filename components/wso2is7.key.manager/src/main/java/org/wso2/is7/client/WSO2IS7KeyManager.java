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
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import feign.Feign;
import feign.Response;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
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
import org.wso2.carbon.apimgt.impl.dto.ScopeDTO;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.kmclient.ApacheFeignHttpClient;
import org.wso2.carbon.apimgt.impl.kmclient.FormEncoder;
import org.wso2.carbon.apimgt.impl.kmclient.KMClientErrorDecoder;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;
import org.wso2.carbon.apimgt.impl.kmclient.model.AuthClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.IntrospectInfo;
import org.wso2.carbon.apimgt.impl.kmclient.model.IntrospectionClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.ScopeClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.TenantHeaderInterceptor;
import org.wso2.carbon.apimgt.impl.kmclient.model.TokenInfo;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import org.wso2.is7.client.model.WSO2IS7ClientInfo;
import org.wso2.is7.client.model.WSO2IS7DCRClient;
import org.wso2.is7.client.model.WSO2IS7SCIMMeClient;
import org.wso2.is7.client.utils.AttributeMapper;
import org.wso2.is7.client.utils.ClaimMappingReader;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class provides the implementation to use WSO2 Identity Server 7 for managing OAuth clients and Tokens
 * needed by WSO2 API Manager.
 * NOTE: Some of the methods (stated in comments above the respective method definitions) are copied from <a href="https://raw.githubusercontent.com/wso2/carbon-apimgt/v9.29.35/components/apimgt/org.wso2.carbon.apimgt.impl/src/main/java/org/wso2/carbon/apimgt/impl/AMDefaultKeyManagerImpl.java">AMDefaultKeyManagerImpl v9.29.35</a>
 * to avoid being dependent on carbon-apimgt.
 */
public class WSO2IS7KeyManager extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(WSO2IS7KeyManager.class);
    private static final String GRANT_TYPE_VALUE = "client_credentials";
    private static final String CLAIM_MAPPINGS_CONFIG_PARAMETER = "claim_mappings";
    private static final String REMOTE_CLAIM = "remoteClaim";
    private static final String LOCAL_CLAIM = "localClaim";

    private WSO2IS7DCRClient wso2IS7DCRClient;
    private IntrospectionClient introspectionClient;
    private ScopeClient scopeClient;
    private AuthClient authClient;
    private WSO2IS7SCIMMeClient wso2IS7SCIMMeClient;
    private Map<String, String> claimMappings;


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
        String applicationOwner = (String) info.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);
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

        // Use a generated user as the app owner for cross tenant subscription scenarios, to avoid the tenant admin
        // being exposed in the JWT token.
        if (APIUtil.isCrossTenantSubscriptionsEnabled()
                && !tenantDomain.equals(MultitenantUtils.getTenantDomain(applicationOwner))) {
            clientInfo.setApplicationOwner(APIUtil.retrieveDefaultReservedUsername());
        } else {
            clientInfo.setApplicationOwner(MultitenantUtils.getTenantAwareUsername(applicationOwner));
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
     * @throws org.wso2.carbon.apimgt.api.APIManagementException
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

        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);

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

    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {

        this.configuration = configuration;

        String username = (String) configuration.getParameter(APIConstants.KEY_MANAGER_USERNAME);
        String password = (String) configuration.getParameter(APIConstants.KEY_MANAGER_PASSWORD);
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

        String scopeEndpoint;
        if (configuration.getParameter(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT) != null) {
            scopeEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.SCOPE_MANAGEMENT_ENDPOINT);
        } else {
            scopeEndpoint = keyManagerServiceUrl.split("/" + APIConstants.SERVICES_URL_RELATIVE_PATH)[0]
                    .concat(getTenantAwareContext().trim())
                    .concat(APIConstants.KEY_MANAGER_OAUTH2_SCOPES_REST_API_BASE_PATH);
        }

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

        scopeClient = Feign.builder()
                .client(new ApacheFeignHttpClient(APIUtil.getHttpClient(scopeEndpoint)))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger())
                .requestInterceptor(new BasicAuthRequestInterceptor(username, password))
                .requestInterceptor(new TenantHeaderInterceptor(tenantDomain))
                .errorDecoder(new KMClientErrorDecoder())
                .target(ScopeClient.class, scopeEndpoint);

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

        String scopeKey = scope.getKey();
        ScopeDTO scopeDTO = new ScopeDTO();
        scopeDTO.setName(scopeKey);
        scopeDTO.setDisplayName(scope.getName());
        scopeDTO.setDescription(scope.getDescription());
        if (StringUtils.isNotBlank(scope.getRoles()) && scope.getRoles().trim().split(",").length > 0) {
            scopeDTO.setBindings(Arrays.asList(scope.getRoles().trim().split(",")));
        }
        try (Response response = scopeClient.registerScope(scopeDTO)) {
            if (response.status() != HttpStatus.SC_CREATED) {
                String responseString = readHttpResponseAsString(response.body());
                throw new APIManagementException("Error occurred while registering scope: " + scopeKey + ". Error" +
                        " Status: " + response.status() + " . Error Response: " + responseString);
            }
        } catch (KeyManagerClientException e) {
            handleException("Cannot register scope : " + scopeKey, e);
        }
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * Read response body for HTTPResponse as a string.
     *
     * @param httpResponse HTTPResponse
     * @return Response Body String
     * @throws APIManagementException If an error occurs while reading the response
     */
    protected String readHttpResponseAsString(Response.Body httpResponse) throws APIManagementException {

        try (InputStream inputStream = httpResponse.asInputStream()) {
            return IOUtils.toString(inputStream);
        } catch (IOException e) {
            String errorMessage = "Error occurred while reading response body as string";
            throw new APIManagementException(errorMessage, e);
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

        ScopeDTO scopeDTO;
        try {
            scopeDTO = scopeClient.getScopeByName(name);
            return fromDTOToScope(scopeDTO);
        } catch (KeyManagerClientException ex) {
            handleException("Cannot read scope : " + name, ex);
        }
        return null;
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * Get Scope object from ScopeDTO response received from authorization server.
     *
     * @param scopeDTO ScopeDTO response
     * @return Scope model object
     */
    private Scope fromDTOToScope(ScopeDTO scopeDTO) {

        Scope scope = new Scope();
        scope.setName(scopeDTO.getDisplayName());
        scope.setKey(scopeDTO.getName());
        scope.setDescription(scopeDTO.getDescription());
        scope.setRoles((scopeDTO.getBindings() != null && !scopeDTO.getBindings().isEmpty())
                ? String.join(",", scopeDTO.getBindings()) : StringUtils.EMPTY);
        return scope;
    }

    /**
     * Copied from AMDefaultKeyManagerImpl.
     * Get Scope object list from ScopeDTO List response received from authorization server.
     *
     * @param scopeDTOS Scope DTO Array
     * @return Scope Object to Scope Name Mappings
     */
    private Map<String, Scope> fromDTOListToScopeListMapping(ScopeDTO[] scopeDTOS) {

        Map<String, Scope> scopeListMapping = new HashMap<>();
        for (ScopeDTO scopeDTO : scopeDTOS) {
            scopeListMapping.put(scopeDTO.getName(), fromDTOToScope(scopeDTO));
        }
        return scopeListMapping;
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

        ScopeDTO[] scopes = new ScopeDTO[0];
        try {
            scopes = scopeClient.getScopes();
        } catch (KeyManagerClientException ex) {
            handleException("Error while retrieving scopes", ex);
        }
        return fromDTOListToScopeListMapping(scopes);
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

        detachResourceScopes(api, oldURITemplates);
        // remove the old local scopes from the KM
        for (String oldScope : oldLocalScopeKeys) {
            deleteScope(oldScope);
        }
        //Register scopes
        for (Scope scope : newLocalScopes) {
            String scopeKey = scope.getKey();
            // Check if key already registered in KM. Scope Key may be already registered for a different version.
            if (!isScopeExists(scopeKey)) {
                //register scope in KM
                registerScope(scope);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Scope: " + scopeKey + " already registered in KM. Skipping registering scope.");
                }
            }
        }
        attachResourceScopes(api, newURITemplates);
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

        try {
            Response response = scopeClient.deleteScope(scopeName);
            if (response.status() != HttpStatus.SC_OK) {
                String responseString = readHttpResponseAsString(response.body());
                String errorMessage =
                        "Error occurred while deleting scope: " + scopeName + ". Error Status: " + response.status() +
                                " . Error Response: " + responseString;
                throw new APIManagementException(errorMessage);
            }
        } catch (KeyManagerClientException ex) {
            handleException("Error occurred while deleting scope", ex);
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

        String scopeKey = scope.getKey();
        try {
            ScopeDTO scopeDTO = new ScopeDTO();
            scopeDTO.setDisplayName(scope.getName());
            scopeDTO.setDescription(scope.getDescription());
            if (StringUtils.isNotBlank(scope.getRoles()) && scope.getRoles().trim().split(",").length > 0) {
                scopeDTO.setBindings(Arrays.asList(scope.getRoles().trim().split(",")));
            }
            try (Response response = scopeClient.updateScope(scopeDTO, scope.getKey())) {
                if (response.status() != HttpStatus.SC_OK) {
                    String responseString = readHttpResponseAsString(response.body());
                    String errorMessage =
                            "Error occurred while updating scope: " + scope.getName() + ". Error Status: " +
                                    response.status() + " . Error Response: " + responseString;
                    throw new APIManagementException(errorMessage);
                }
            }
        } catch (KeyManagerClientException e) {
            String errorMessage = "Error occurred while updating scope: " + scopeKey;
            handleException(errorMessage, e);
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

        try (Response response = scopeClient.isScopeExist(scopeName)) {
            if (response.status() == HttpStatus.SC_OK) {
                return true;
            } else if (response.status() != HttpStatus.SC_NOT_FOUND) {
                String responseString = readHttpResponseAsString(response.body());
                String errorMessage = "Error occurred while checking existence of scope: " + scopeName + ". Error " +
                        "Status: " + response.status() + " . Error Response: " + responseString;
                throw new APIManagementException(errorMessage);
            }
        } catch (KeyManagerClientException e) {
            handleException("Error while check scope exist", e);
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
                Map<String, String> claims = AttributeMapper.getUserClaims(scimUserObjectString.toString());
                Map<String, String> claimMappings = getClaimMappings();
                userClaims = getMappedAttributes(claims, claimMappings);
            } catch (KeyManagerClientException e) {
                handleException("Error while getting user info", e);
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

}
