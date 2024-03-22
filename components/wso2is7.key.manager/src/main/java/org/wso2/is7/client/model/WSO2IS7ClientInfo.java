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

package org.wso2.is7.client.model;

import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * Represents the client information returned from WSO2 Identity Server 7.
 */
public class WSO2IS7ClientInfo {

    public WSO2IS7ClientInfo() {}

    @SerializedName("redirect_uris")
    private List<String> redirectUris;

    @SerializedName("client_name")
    private String clientName;

    @SerializedName("client_id")
    private String clientId;

    @SerializedName("client_secret")
    private String clientSecret;

    @SerializedName("grant_types")
    private List<String> grantTypes;

    @SerializedName("application_type")
    private String applicationType;

    @SerializedName("jwks_uri")
    private String jwksUri;

    @SerializedName("url")
    private String url;

    @SerializedName("ext_param_client_id")
    private String presetClientId;

    @SerializedName("ext_param_client_secret")
    private String presetClientSecret;

    @SerializedName("contacts")
    private List<String> contacts;

    @SerializedName("post_logout_redirect_uris")
    private List<String> postLogoutRedirectUris;

    @SerializedName("request_uris")
    private List<String> requestUris;

    @SerializedName("response_types")
    private List<String> responseTypes;

    @SerializedName("ext_param_sp_template")
    private String extParamSpTemplate;

    @SerializedName("backchannel_logout_uri")
    private String backChannelLogoutUri;

    @SerializedName("backchannel_logout_session_required")
    private boolean backChannelLogoutSessionRequired;

    @SerializedName("ext_application_display_name")
    private String applicationDisplayName;

    @SerializedName("token_type_extension")
    private String tokenTypeExtension;

    @SerializedName("ext_application_owner")
    private String applicationOwner;

    @SerializedName("ext_application_token_lifetime")
    private Long applicationTokenLifetime;

    @SerializedName("ext_user_token_lifetime")
    private Long userTokenLifetime;

    @SerializedName("ext_refresh_token_lifetime")
    private long refreshTokenLifetime;

    @SerializedName("ext_id_token_lifetime")
    private long idTokenLifetime;

    @SerializedName("ext_pkce_mandatory")
    private boolean pkceMandatory;

    @SerializedName("ext_pkce_support_plain")
    private boolean pkceSupportPlain;

    @SerializedName("ext_public_client")
    private boolean extPublicClient;

    @SerializedName("token_endpoint_auth_method")
    private String tokenEndpointAuthMethod;

    @SerializedName("token_endpoint_auth_signing_alg")
    private String tokenEndpointAuthSigningAlg;

    @SerializedName("sector_identifier_uri")
    private String sectorIdentifierUri;

    @SerializedName("id_token_signed_response_alg")
    private String idTokenSignedResponseAlg;

    @SerializedName("id_token_encrypted_response_alg")
    private String idTokenEncryptedResponseAlg;

    @SerializedName("id_token_encrypted_response_enc")
    private String idTokenEncryptedResponseEnc;

    @SerializedName("software_statement")
    private String softwareStatement;

    @SerializedName("request_object_signing_alg")
    private String requestObjectSigningAlg;

    @SerializedName("tls_client_auth_subject_dn")
    private String tlsClientAuthSubjectDn;

    @SerializedName("require_signed_request_object")
    private boolean requireSignedRequestObject;

    @SerializedName("require_pushed_authorization_requests")
    private boolean requirePushedAuthorizationRequests;

    @SerializedName("tls_client_certificate_bound_access_tokens")
    private boolean tlsClientCertificateBoundAccessTokens;

    @SerializedName("subject_type")
    private String subjectType;

    @SerializedName("request_object_encryption_alg")
    private String requestObjectEncryptionAlg;

    @SerializedName("request_object_encryption_enc")
    private String requestObjectEncryptionEnc;

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public String getApplicationType() {
        return applicationType;
    }

    public void setApplicationType(String applicationType) {
        this.applicationType = applicationType;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getPresetClientId() {
        return presetClientId;
    }

    public void setPresetClientId(String presetClientId) {
        this.presetClientId = presetClientId;
    }

    public String getPresetClientSecret() {
        return presetClientSecret;
    }

    public void setPresetClientSecret(String presetClientSecret) {
        this.presetClientSecret = presetClientSecret;
    }

    public List<String> getContacts() {
        return contacts;
    }

    public void setContacts(List<String> contacts) {
        this.contacts = contacts;
    }

    public List<String> getPostLogoutRedirectUris() {
        return postLogoutRedirectUris;
    }

    public void setPostLogoutRedirectUris(List<String> postLogoutRedirectUris) {
        this.postLogoutRedirectUris = postLogoutRedirectUris;
    }

    public List<String> getRequestUris() {
        return requestUris;
    }

    public void setRequestUris(List<String> requestUris) {
        this.requestUris = requestUris;
    }

    public List<String> getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(List<String> responseTypes) {
        this.responseTypes = responseTypes;
    }

    public String getExtParamSpTemplate() {
        return extParamSpTemplate;
    }

    public void setExtParamSpTemplate(String extParamSpTemplate) {
        this.extParamSpTemplate = extParamSpTemplate;
    }

    public String getBackChannelLogoutUri() {
        return backChannelLogoutUri;
    }

    public void setBackChannelLogoutUri(String backChannelLogoutUri) {
        this.backChannelLogoutUri = backChannelLogoutUri;
    }

    public boolean isBackChannelLogoutSessionRequired() {
        return backChannelLogoutSessionRequired;
    }

    public void setBackChannelLogoutSessionRequired(boolean backChannelLogoutSessionRequired) {
        this.backChannelLogoutSessionRequired = backChannelLogoutSessionRequired;
    }

    public String getApplicationDisplayName() {
        return applicationDisplayName;
    }

    public void setApplicationDisplayName(String applicationDisplayName) {
        this.applicationDisplayName = applicationDisplayName;
    }

    public String getTokenTypeExtension() {
        return tokenTypeExtension;
    }

    public void setTokenTypeExtension(String tokenTypeExtension) {
        this.tokenTypeExtension = tokenTypeExtension;
    }

    public String getApplicationOwner() {
        return applicationOwner;
    }

    public void setApplicationOwner(String applicationOwner) {
        this.applicationOwner = applicationOwner;
    }

    public Long getApplicationTokenLifetime() {
        return applicationTokenLifetime;
    }

    public void setApplicationTokenLifetime(Long applicationTokenLifetime) {
        this.applicationTokenLifetime = applicationTokenLifetime;
    }

    public Long getUserTokenLifetime() {
        return userTokenLifetime;
    }

    public void setUserTokenLifetime(Long userTokenLifetime) {
        this.userTokenLifetime = userTokenLifetime;
    }

    public long getRefreshTokenLifetime() {
        return refreshTokenLifetime;
    }

    public void setRefreshTokenLifetime(long refreshTokenLifetime) {
        this.refreshTokenLifetime = refreshTokenLifetime;
    }

    public long getIdTokenLifetime() {
        return idTokenLifetime;
    }

    public void setIdTokenLifetime(long idTokenLifetime) {
        this.idTokenLifetime = idTokenLifetime;
    }

    public boolean isPkceMandatory() {
        return pkceMandatory;
    }

    public void setPkceMandatory(boolean pkceMandatory) {
        this.pkceMandatory = pkceMandatory;
    }

    public boolean isPkceSupportPlain() {
        return pkceSupportPlain;
    }

    public void setPkceSupportPlain(boolean pkceSupportPlain) {
        this.pkceSupportPlain = pkceSupportPlain;
    }

    public boolean isExtPublicClient() {
        return extPublicClient;
    }

    public void setExtPublicClient(boolean extPublicClient) {
        this.extPublicClient = extPublicClient;
    }

    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public String getTokenEndpointAuthSigningAlg() {
        return tokenEndpointAuthSigningAlg;
    }

    public void setTokenEndpointAuthSigningAlg(String tokenEndpointAuthSigningAlg) {
        this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
    }

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public void setSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
    }

    public String getIdTokenSignedResponseAlg() {
        return idTokenSignedResponseAlg;
    }

    public void setIdTokenSignedResponseAlg(String idTokenSignedResponseAlg) {
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
    }

    public String getIdTokenEncryptedResponseAlg() {
        return idTokenEncryptedResponseAlg;
    }

    public void setIdTokenEncryptedResponseAlg(String idTokenEncryptedResponseAlg) {
        this.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg;
    }

    public String getIdTokenEncryptedResponseEnc() {
        return idTokenEncryptedResponseEnc;
    }

    public void setIdTokenEncryptedResponseEnc(String idTokenEncryptedResponseEnc) {
        this.idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc;
    }

    public String getSoftwareStatement() {
        return softwareStatement;
    }

    public void setSoftwareStatement(String softwareStatement) {
        this.softwareStatement = softwareStatement;
    }

    public String getRequestObjectSigningAlg() {
        return requestObjectSigningAlg;
    }

    public void setRequestObjectSigningAlg(String requestObjectSigningAlg) {
        this.requestObjectSigningAlg = requestObjectSigningAlg;
    }

    public String getTlsClientAuthSubjectDn() {
        return tlsClientAuthSubjectDn;
    }

    public void setTlsClientAuthSubjectDn(String tlsClientAuthSubjectDn) {
        this.tlsClientAuthSubjectDn = tlsClientAuthSubjectDn;
    }

    public boolean isRequireSignedRequestObject() {
        return requireSignedRequestObject;
    }

    public void setRequireSignedRequestObject(boolean requireSignedRequestObject) {
        this.requireSignedRequestObject = requireSignedRequestObject;
    }

    public boolean isRequirePushedAuthorizationRequests() {
        return requirePushedAuthorizationRequests;
    }

    public void setRequirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {
        this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
    }

    public boolean isTlsClientCertificateBoundAccessTokens() {
        return tlsClientCertificateBoundAccessTokens;
    }

    public void setTlsClientCertificateBoundAccessTokens(boolean tlsClientCertificateBoundAccessTokens) {
        this.tlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public void setSubjectType(String subjectType) {
        this.subjectType = subjectType;
    }

    public String getRequestObjectEncryptionAlg() {
        return requestObjectEncryptionAlg;
    }

    public void setRequestObjectEncryptionAlg(String requestObjectEncryptionAlg) {
        this.requestObjectEncryptionAlg = requestObjectEncryptionAlg;
    }

    public String getRequestObjectEncryptionEnc() {
        return requestObjectEncryptionEnc;
    }

    public void setRequestObjectEncryptionEnc(String requestObjectEncryptionEnc) {
        this.requestObjectEncryptionEnc = requestObjectEncryptionEnc;
    }

}
