package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class UpdateRequestDTO   {
  
    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private String clientId = null;
    private String clientSecret = null;
    private List<String> grantTypes = new ArrayList<>();
    private String applicationDisplayName = null;
    private String tokenTypeExtension = null;
    private String extApplicationOwner = null;
    private String backchannelLogoutUri = null;
    private Boolean backchannelLogoutSessionRequired = null;
    private Long extApplicationTokenLifetime = null;
    private Long extUserTokenLifetime = null;
    private Long extRefreshTokenLifetime = null;
    private Long extIdTokenLifetime = null;

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
  public UpdateRequestDTO applicationDisplayName(String applicationDisplayName) {
    this.applicationDisplayName = applicationDisplayName;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("application_display_name")
  public String getApplicationDisplayName() {
    return applicationDisplayName;
  }
  public void setApplicationDisplayName(String applicationDisplayName) {
    this.applicationDisplayName = applicationDisplayName;
  }

  /**
   **/
  public UpdateRequestDTO tokenTypeExtension(String tokenTypeExtension) {
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

  /**
   **/
  public UpdateRequestDTO extApplicationTokenLifetime(Long extApplicationTokenLifetime) {
    this.extApplicationTokenLifetime = extApplicationTokenLifetime;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_application_token_lifetime")
  public Long getExtApplicationTokenLifetime() {
    return extApplicationTokenLifetime;
  }
  public void setExtApplicationTokenLifetime(Long extApplicationTokenLifetime) {
    this.extApplicationTokenLifetime = extApplicationTokenLifetime;
  }

  /**
   **/
  public UpdateRequestDTO extUserTokenLifetime(Long extUserTokenLifetime) {
    this.extUserTokenLifetime = extUserTokenLifetime;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_user_token_lifetime")
  public Long getExtUserTokenLifetime() {
    return extUserTokenLifetime;
  }
  public void setExtUserTokenLifetime(Long extUserTokenLifetime) {
    this.extUserTokenLifetime = extUserTokenLifetime;
  }

  /**
   **/
  public UpdateRequestDTO extRefreshTokenLifetime(Long extRefreshTokenLifetime) {
    this.extRefreshTokenLifetime = extRefreshTokenLifetime;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_refresh_token_lifetime")
  public Long getExtRefreshTokenLifetime() {
    return extRefreshTokenLifetime;
  }
  public void setExtRefreshTokenLifetime(Long extRefreshTokenLifetime) {
    this.extRefreshTokenLifetime = extRefreshTokenLifetime;
  }

  /**
   **/
  public UpdateRequestDTO extIdTokenLifetime(Long extIdTokenLifetime) {
    this.extIdTokenLifetime = extIdTokenLifetime;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_id_token_lifetime")
  public Long getExtIdTokenLifetime() {
    return extIdTokenLifetime;
  }
  public void setExtIdTokenLifetime(Long extIdTokenLifetime) {
    this.extIdTokenLifetime = extIdTokenLifetime;
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
        Objects.equals(applicationDisplayName, updateRequest.applicationDisplayName) &&
        Objects.equals(tokenTypeExtension, updateRequest.tokenTypeExtension) &&
        Objects.equals(extApplicationOwner, updateRequest.extApplicationOwner) &&
        Objects.equals(backchannelLogoutUri, updateRequest.backchannelLogoutUri) &&
        Objects.equals(backchannelLogoutSessionRequired, updateRequest.backchannelLogoutSessionRequired) &&
        Objects.equals(extApplicationTokenLifetime, updateRequest.extApplicationTokenLifetime) &&
        Objects.equals(extUserTokenLifetime, updateRequest.extUserTokenLifetime) &&
        Objects.equals(extRefreshTokenLifetime, updateRequest.extRefreshTokenLifetime) &&
        Objects.equals(extIdTokenLifetime, updateRequest.extIdTokenLifetime);
  }

  @Override
  public int hashCode() {
    return Objects.hash(redirectUris, clientName, clientId, clientSecret, grantTypes, applicationDisplayName, tokenTypeExtension, extApplicationOwner, backchannelLogoutUri, backchannelLogoutSessionRequired, extApplicationTokenLifetime, extUserTokenLifetime, extRefreshTokenLifetime, extIdTokenLifetime);
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
    sb.append("    applicationDisplayName: ").append(toIndentedString(applicationDisplayName)).append("\n");
    sb.append("    tokenTypeExtension: ").append(toIndentedString(tokenTypeExtension)).append("\n");
    sb.append("    extApplicationOwner: ").append(toIndentedString(extApplicationOwner)).append("\n");
    sb.append("    backchannelLogoutUri: ").append(toIndentedString(backchannelLogoutUri)).append("\n");
    sb.append("    backchannelLogoutSessionRequired: ").append(toIndentedString(backchannelLogoutSessionRequired)).append("\n");
    sb.append("    extApplicationTokenLifetime: ").append(toIndentedString(extApplicationTokenLifetime)).append("\n");
    sb.append("    extUserTokenLifetime: ").append(toIndentedString(extUserTokenLifetime)).append("\n");
    sb.append("    extRefreshTokenLifetime: ").append(toIndentedString(extRefreshTokenLifetime)).append("\n");
    sb.append("    extIdTokenLifetime: ").append(toIndentedString(extIdTokenLifetime)).append("\n");
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
