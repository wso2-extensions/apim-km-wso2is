package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

import io.swagger.annotations.*;
import java.util.Objects;

public class ApplicationDTO   {
  
    private String clientId = null;
    private String clientSecret = null;
    private String clientSecretExpiresAt = null;
    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private List<String> grantTypes = new ArrayList<>();
    private String extApplicationOwner = null;

  /**
   **/
  public ApplicationDTO clientId(String clientId) {
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
  public ApplicationDTO clientSecret(String clientSecret) {
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
  public ApplicationDTO clientSecretExpiresAt(String clientSecretExpiresAt) {
    this.clientSecretExpiresAt = clientSecretExpiresAt;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("client_secret_expires_at")
  public String getClientSecretExpiresAt() {
    return clientSecretExpiresAt;
  }
  public void setClientSecretExpiresAt(String clientSecretExpiresAt) {
    this.clientSecretExpiresAt = clientSecretExpiresAt;
  }

  /**
   **/
  public ApplicationDTO redirectUris(List<String> redirectUris) {
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
  public ApplicationDTO clientName(String clientName) {
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
  public ApplicationDTO grantTypes(List<String> grantTypes) {
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
  public ApplicationDTO extApplicationOwner(String extApplicationOwner) {
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


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ApplicationDTO application = (ApplicationDTO) o;
    return Objects.equals(clientId, application.clientId) &&
        Objects.equals(clientSecret, application.clientSecret) &&
        Objects.equals(clientSecretExpiresAt, application.clientSecretExpiresAt) &&
        Objects.equals(redirectUris, application.redirectUris) &&
        Objects.equals(clientName, application.clientName) &&
        Objects.equals(grantTypes, application.grantTypes) &&
        Objects.equals(extApplicationOwner, application.extApplicationOwner);
  }

  @Override
  public int hashCode() {
    return Objects.hash(clientId, clientSecret, clientSecretExpiresAt, redirectUris, clientName, grantTypes, extApplicationOwner);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ApplicationDTO {\n");
    
    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
    sb.append("    clientSecret: ").append(toIndentedString(clientSecret)).append("\n");
    sb.append("    clientSecretExpiresAt: ").append(toIndentedString(clientSecretExpiresAt)).append("\n");
    sb.append("    redirectUris: ").append(toIndentedString(redirectUris)).append("\n");
    sb.append("    clientName: ").append(toIndentedString(clientName)).append("\n");
    sb.append("    grantTypes: ").append(toIndentedString(grantTypes)).append("\n");
    sb.append("    extApplicationOwner: ").append(toIndentedString(extApplicationOwner)).append("\n");
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
