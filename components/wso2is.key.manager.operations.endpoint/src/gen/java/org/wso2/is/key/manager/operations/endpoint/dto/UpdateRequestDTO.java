package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

import io.swagger.annotations.*;
import java.util.Objects;

public class UpdateRequestDTO   {
  
    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private String clientId = null;
    private String clientSecret = null;
    private List<String> grantTypes = new ArrayList<>();
    private String tokenType = null;
    private String extApplicationOwner = null;
    private String backchannelLogoutUri = null;
    private Boolean backchannelLogoutSessionRequired = null;

  /**
   **/
  public UpdateRequestDTO redirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("redirect_uris")
  public List<String> getRedirectUris() {
    return redirectUris;
  }
  public void setRedirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  /**
   **/
  public UpdateRequestDTO clientName(String clientName) {
    this.clientName = clientName;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("client_name")
  public String getClientName() {
    return clientName;
  }
  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  /**
   **/
  public UpdateRequestDTO clientId(String clientId) {
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
  public UpdateRequestDTO clientSecret(String clientSecret) {
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
  public UpdateRequestDTO grantTypes(List<String> grantTypes) {
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
  public UpdateRequestDTO tokenType(String tokenType) {
    this.tokenType = tokenType;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("tokenType")
  public String getTokenType() {
    return tokenType;
  }
  public void setTokenType(String tokenType) {
    this.tokenType = tokenType;
  }

  /**
   **/
  public UpdateRequestDTO extApplicationOwner(String extApplicationOwner) {
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
  public UpdateRequestDTO backchannelLogoutUri(String backchannelLogoutUri) {
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
  public UpdateRequestDTO backchannelLogoutSessionRequired(Boolean backchannelLogoutSessionRequired) {
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
    UpdateRequestDTO updateRequest = (UpdateRequestDTO) o;
    return Objects.equals(redirectUris, updateRequest.redirectUris) &&
        Objects.equals(clientName, updateRequest.clientName) &&
        Objects.equals(clientId, updateRequest.clientId) &&
        Objects.equals(clientSecret, updateRequest.clientSecret) &&
        Objects.equals(grantTypes, updateRequest.grantTypes) &&
        Objects.equals(tokenType, updateRequest.tokenType) &&
        Objects.equals(extApplicationOwner, updateRequest.extApplicationOwner) &&
        Objects.equals(backchannelLogoutUri, updateRequest.backchannelLogoutUri) &&
        Objects.equals(backchannelLogoutSessionRequired, updateRequest.backchannelLogoutSessionRequired);
  }

  @Override
  public int hashCode() {
    return Objects.hash(redirectUris, clientName, clientId, clientSecret, grantTypes, tokenType, extApplicationOwner, backchannelLogoutUri, backchannelLogoutSessionRequired);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UpdateRequestDTO {\n");
    
    sb.append("    redirectUris: ").append(toIndentedString(redirectUris)).append("\n");
    sb.append("    clientName: ").append(toIndentedString(clientName)).append("\n");
    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
    sb.append("    clientSecret: ").append(toIndentedString(clientSecret)).append("\n");
    sb.append("    grantTypes: ").append(toIndentedString(grantTypes)).append("\n");
    sb.append("    tokenType: ").append(toIndentedString(tokenType)).append("\n");
    sb.append("    extApplicationOwner: ").append(toIndentedString(extApplicationOwner)).append("\n");
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
