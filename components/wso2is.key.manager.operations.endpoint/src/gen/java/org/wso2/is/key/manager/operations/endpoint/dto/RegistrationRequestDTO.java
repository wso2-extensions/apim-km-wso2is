package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class RegistrationRequestDTO   {
  
    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private String clientId = null;
    private String clientSecret = null;
    private List<String> grantTypes = new ArrayList<>();
    private String applicationType = null;
    private String tokenTypeExtension = null;
    private String extApplicationOwner = null;
    private String jwksUri = null;
    private String url = null;
    private String extParamClientId = null;
    private String extParamClientSecret = null;
    private List<String> contacts = new ArrayList<>();
    private List<String> postLogoutRedirectUris = new ArrayList<>();
    private List<String> requestUris = new ArrayList<>();
    private List<String> responseTypes = new ArrayList<>();
    private String extParamSpTemplate = null;
    private String backchannelLogoutUri = null;
    private Boolean backchannelLogoutSessionRequired = null;

  /**
   **/
  public RegistrationRequestDTO redirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
    return this;
  }

  
  @ApiModelProperty(required = true, value = "")
  @JsonProperty("redirect_uris")
  @NotNull
  public List<String> getRedirectUris() {
    return redirectUris;
  }
  public void setRedirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  /**
   **/
  public RegistrationRequestDTO clientName(String clientName) {
    this.clientName = clientName;
    return this;
  }

  
  @ApiModelProperty(required = true, value = "")
  @JsonProperty("client_name")
  @NotNull
  public String getClientName() {
    return clientName;
  }
  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  /**
   **/
  public RegistrationRequestDTO clientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("client_id")
  public String getClientId() {
    return clientId;
  }
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  /**
   **/
  public RegistrationRequestDTO clientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("client_secret")
  public String getClientSecret() {
    return clientSecret;
  }
  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  /**
   **/
  public RegistrationRequestDTO grantTypes(List<String> grantTypes) {
    this.grantTypes = grantTypes;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("grant_types")
  public List<String> getGrantTypes() {
    return grantTypes;
  }
  public void setGrantTypes(List<String> grantTypes) {
    this.grantTypes = grantTypes;
  }

  /**
   **/
  public RegistrationRequestDTO applicationType(String applicationType) {
    this.applicationType = applicationType;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("application_type")
  public String getApplicationType() {
    return applicationType;
  }
  public void setApplicationType(String applicationType) {
    this.applicationType = applicationType;
  }

  /**
   **/
  public RegistrationRequestDTO tokenTypeExtension(String tokenTypeExtension) {
    this.tokenTypeExtension = tokenTypeExtension;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("token_type_extension")
  public String getTokenTypeExtension() {
    return tokenTypeExtension;
  }
  public void setTokenTypeExtension(String tokenTypeExtension) {
    this.tokenTypeExtension = tokenTypeExtension;
  }

  /**
   **/
  public RegistrationRequestDTO extApplicationOwner(String extApplicationOwner) {
    this.extApplicationOwner = extApplicationOwner;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_application_owner")
  public String getExtApplicationOwner() {
    return extApplicationOwner;
  }
  public void setExtApplicationOwner(String extApplicationOwner) {
    this.extApplicationOwner = extApplicationOwner;
  }

  /**
   **/
  public RegistrationRequestDTO jwksUri(String jwksUri) {
    this.jwksUri = jwksUri;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("jwks_uri")
  public String getJwksUri() {
    return jwksUri;
  }
  public void setJwksUri(String jwksUri) {
    this.jwksUri = jwksUri;
  }

  /**
   **/
  public RegistrationRequestDTO url(String url) {
    this.url = url;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("url")
  public String getUrl() {
    return url;
  }
  public void setUrl(String url) {
    this.url = url;
  }

  /**
   **/
  public RegistrationRequestDTO extParamClientId(String extParamClientId) {
    this.extParamClientId = extParamClientId;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_param_client_id")
  public String getExtParamClientId() {
    return extParamClientId;
  }
  public void setExtParamClientId(String extParamClientId) {
    this.extParamClientId = extParamClientId;
  }

  /**
   **/
  public RegistrationRequestDTO extParamClientSecret(String extParamClientSecret) {
    this.extParamClientSecret = extParamClientSecret;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_param_client_secret")
  public String getExtParamClientSecret() {
    return extParamClientSecret;
  }
  public void setExtParamClientSecret(String extParamClientSecret) {
    this.extParamClientSecret = extParamClientSecret;
  }

  /**
   **/
  public RegistrationRequestDTO contacts(List<String> contacts) {
    this.contacts = contacts;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("contacts")
  public List<String> getContacts() {
    return contacts;
  }
  public void setContacts(List<String> contacts) {
    this.contacts = contacts;
  }

  /**
   **/
  public RegistrationRequestDTO postLogoutRedirectUris(List<String> postLogoutRedirectUris) {
    this.postLogoutRedirectUris = postLogoutRedirectUris;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("post_logout_redirect_uris")
  public List<String> getPostLogoutRedirectUris() {
    return postLogoutRedirectUris;
  }
  public void setPostLogoutRedirectUris(List<String> postLogoutRedirectUris) {
    this.postLogoutRedirectUris = postLogoutRedirectUris;
  }

  /**
   **/
  public RegistrationRequestDTO requestUris(List<String> requestUris) {
    this.requestUris = requestUris;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("request_uris")
  public List<String> getRequestUris() {
    return requestUris;
  }
  public void setRequestUris(List<String> requestUris) {
    this.requestUris = requestUris;
  }

  /**
   **/
  public RegistrationRequestDTO responseTypes(List<String> responseTypes) {
    this.responseTypes = responseTypes;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("response_types")
  public List<String> getResponseTypes() {
    return responseTypes;
  }
  public void setResponseTypes(List<String> responseTypes) {
    this.responseTypes = responseTypes;
  }

  /**
   **/
  public RegistrationRequestDTO extParamSpTemplate(String extParamSpTemplate) {
    this.extParamSpTemplate = extParamSpTemplate;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_param_sp_template")
  public String getExtParamSpTemplate() {
    return extParamSpTemplate;
  }
  public void setExtParamSpTemplate(String extParamSpTemplate) {
    this.extParamSpTemplate = extParamSpTemplate;
  }

  /**
   **/
  public RegistrationRequestDTO backchannelLogoutUri(String backchannelLogoutUri) {
    this.backchannelLogoutUri = backchannelLogoutUri;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("backchannel_logout_uri")
  public String getBackchannelLogoutUri() {
    return backchannelLogoutUri;
  }
  public void setBackchannelLogoutUri(String backchannelLogoutUri) {
    this.backchannelLogoutUri = backchannelLogoutUri;
  }

  /**
   **/
  public RegistrationRequestDTO backchannelLogoutSessionRequired(Boolean backchannelLogoutSessionRequired) {
    this.backchannelLogoutSessionRequired = backchannelLogoutSessionRequired;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("backchannel_logout_session_required")
  public Boolean isBackchannelLogoutSessionRequired() {
    return backchannelLogoutSessionRequired;
  }
  public void setBackchannelLogoutSessionRequired(Boolean backchannelLogoutSessionRequired) {
    this.backchannelLogoutSessionRequired = backchannelLogoutSessionRequired;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RegistrationRequestDTO registrationRequest = (RegistrationRequestDTO) o;
    return Objects.equals(redirectUris, registrationRequest.redirectUris) &&
        Objects.equals(clientName, registrationRequest.clientName) &&
        Objects.equals(clientId, registrationRequest.clientId) &&
        Objects.equals(clientSecret, registrationRequest.clientSecret) &&
        Objects.equals(grantTypes, registrationRequest.grantTypes) &&
        Objects.equals(applicationType, registrationRequest.applicationType) &&
        Objects.equals(tokenTypeExtension, registrationRequest.tokenTypeExtension) &&
        Objects.equals(extApplicationOwner, registrationRequest.extApplicationOwner) &&
        Objects.equals(jwksUri, registrationRequest.jwksUri) &&
        Objects.equals(url, registrationRequest.url) &&
        Objects.equals(extParamClientId, registrationRequest.extParamClientId) &&
        Objects.equals(extParamClientSecret, registrationRequest.extParamClientSecret) &&
        Objects.equals(contacts, registrationRequest.contacts) &&
        Objects.equals(postLogoutRedirectUris, registrationRequest.postLogoutRedirectUris) &&
        Objects.equals(requestUris, registrationRequest.requestUris) &&
        Objects.equals(responseTypes, registrationRequest.responseTypes) &&
        Objects.equals(extParamSpTemplate, registrationRequest.extParamSpTemplate) &&
        Objects.equals(backchannelLogoutUri, registrationRequest.backchannelLogoutUri) &&
        Objects.equals(backchannelLogoutSessionRequired, registrationRequest.backchannelLogoutSessionRequired);
  }

  @Override
  public int hashCode() {
    return Objects.hash(redirectUris, clientName, clientId, clientSecret, grantTypes, applicationType, tokenTypeExtension, extApplicationOwner, jwksUri, url, extParamClientId, extParamClientSecret, contacts, postLogoutRedirectUris, requestUris, responseTypes, extParamSpTemplate, backchannelLogoutUri, backchannelLogoutSessionRequired);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RegistrationRequestDTO {\n");
    
    sb.append("    redirectUris: ").append(toIndentedString(redirectUris)).append("\n");
    sb.append("    clientName: ").append(toIndentedString(clientName)).append("\n");
    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
    sb.append("    clientSecret: ").append(toIndentedString(clientSecret)).append("\n");
    sb.append("    grantTypes: ").append(toIndentedString(grantTypes)).append("\n");
    sb.append("    applicationType: ").append(toIndentedString(applicationType)).append("\n");
    sb.append("    tokenTypeExtension: ").append(toIndentedString(tokenTypeExtension)).append("\n");
    sb.append("    extApplicationOwner: ").append(toIndentedString(extApplicationOwner)).append("\n");
    sb.append("    jwksUri: ").append(toIndentedString(jwksUri)).append("\n");
    sb.append("    url: ").append(toIndentedString(url)).append("\n");
    sb.append("    extParamClientId: ").append(toIndentedString(extParamClientId)).append("\n");
    sb.append("    extParamClientSecret: ").append(toIndentedString(extParamClientSecret)).append("\n");
    sb.append("    contacts: ").append(toIndentedString(contacts)).append("\n");
    sb.append("    postLogoutRedirectUris: ").append(toIndentedString(postLogoutRedirectUris)).append("\n");
    sb.append("    requestUris: ").append(toIndentedString(requestUris)).append("\n");
    sb.append("    responseTypes: ").append(toIndentedString(responseTypes)).append("\n");
    sb.append("    extParamSpTemplate: ").append(toIndentedString(extParamSpTemplate)).append("\n");
    sb.append("    backchannelLogoutUri: ").append(toIndentedString(backchannelLogoutUri)).append("\n");
    sb.append("    backchannelLogoutSessionRequired: ").append(toIndentedString(backchannelLogoutSessionRequired)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}
