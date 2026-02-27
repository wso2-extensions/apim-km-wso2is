package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class ApplicationDTO   {
  
    private String clientId = null;
    private String clientSecret = null;
    private String clientSecretExpiresAt = null;
    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private List<String> grantTypes = new ArrayList<>();
    private String extApplicationOwner = null;
    private Long extApplicationTokenLifetime = null;
    private Long extUserTokenLifetime = null;
    private Long extRefreshTokenLifetime = null;
    private Long extIdTokenLifetime = null;
    private Boolean pkceMandatory = null;
    private Boolean pkceSupportPlain = null;
    private Boolean bypassClientCredentials = null;
    private String tokenTypeExtension = null;
    private List<String> applicationScopes = new ArrayList<>();
    private String extClientSecretDescription = null;

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

  /**
   **/
  public ApplicationDTO extApplicationTokenLifetime(Long extApplicationTokenLifetime) {
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
  public ApplicationDTO extUserTokenLifetime(Long extUserTokenLifetime) {
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
  public ApplicationDTO extRefreshTokenLifetime(Long extRefreshTokenLifetime) {
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
  public ApplicationDTO extIdTokenLifetime(Long extIdTokenLifetime) {
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

  /**
   **/
  public ApplicationDTO pkceMandatory(Boolean pkceMandatory) {
    this.pkceMandatory = pkceMandatory;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("pkceMandatory")
  public Boolean isPkceMandatory() {
    return pkceMandatory;
  }
  public void setPkceMandatory(Boolean pkceMandatory) {
    this.pkceMandatory = pkceMandatory;
  }

  /**
   **/
  public ApplicationDTO pkceSupportPlain(Boolean pkceSupportPlain) {
    this.pkceSupportPlain = pkceSupportPlain;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("pkceSupportPlain")
  public Boolean isPkceSupportPlain() {
    return pkceSupportPlain;
  }
  public void setPkceSupportPlain(Boolean pkceSupportPlain) {
    this.pkceSupportPlain = pkceSupportPlain;
  }

  /**
   **/
  public ApplicationDTO bypassClientCredentials(Boolean bypassClientCredentials) {
    this.bypassClientCredentials = bypassClientCredentials;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("bypassClientCredentials")
  public Boolean isBypassClientCredentials() {
    return bypassClientCredentials;
  }
  public void setBypassClientCredentials(Boolean bypassClientCredentials) {
    this.bypassClientCredentials = bypassClientCredentials;
  }

  /**
   **/
  public ApplicationDTO tokenTypeExtension(String tokenTypeExtension) {
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
  public ApplicationDTO applicationScopes(List<String> applicationScopes) {
    this.applicationScopes = applicationScopes;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("application_scopes")
  public List<String> getApplicationScopes() {
    return applicationScopes;
  }
  public void setApplicationScopes(List<String> applicationScopes) {
    this.applicationScopes = applicationScopes;
  }

  /**
   **/
  public ApplicationDTO extClientSecretDescription(String extClientSecretDescription) {
    this.extClientSecretDescription = extClientSecretDescription;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("ext_client_secret_description")
  public String getExtClientSecretDescription() {
    return extClientSecretDescription;
  }
  public void setExtClientSecretDescription(String extClientSecretDescription) {
    this.extClientSecretDescription = extClientSecretDescription;
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
        Objects.equals(extApplicationOwner, application.extApplicationOwner) &&
        Objects.equals(extApplicationTokenLifetime, application.extApplicationTokenLifetime) &&
        Objects.equals(extUserTokenLifetime, application.extUserTokenLifetime) &&
        Objects.equals(extRefreshTokenLifetime, application.extRefreshTokenLifetime) &&
        Objects.equals(extIdTokenLifetime, application.extIdTokenLifetime) &&
        Objects.equals(pkceMandatory, application.pkceMandatory) &&
        Objects.equals(pkceSupportPlain, application.pkceSupportPlain) &&
        Objects.equals(bypassClientCredentials, application.bypassClientCredentials) &&
        Objects.equals(tokenTypeExtension, application.tokenTypeExtension) &&
        Objects.equals(applicationScopes, application.applicationScopes) &&
        Objects.equals(extClientSecretDescription, application.extClientSecretDescription);
  }

  @Override
  public int hashCode() {
    return Objects.hash(clientId, clientSecret, clientSecretExpiresAt, redirectUris, clientName, grantTypes, extApplicationOwner, extApplicationTokenLifetime, extUserTokenLifetime, extRefreshTokenLifetime, extIdTokenLifetime, pkceMandatory, pkceSupportPlain, bypassClientCredentials, tokenTypeExtension, applicationScopes, extClientSecretDescription);
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
    sb.append("    extApplicationTokenLifetime: ").append(toIndentedString(extApplicationTokenLifetime)).append("\n");
    sb.append("    extUserTokenLifetime: ").append(toIndentedString(extUserTokenLifetime)).append("\n");
    sb.append("    extRefreshTokenLifetime: ").append(toIndentedString(extRefreshTokenLifetime)).append("\n");
    sb.append("    extIdTokenLifetime: ").append(toIndentedString(extIdTokenLifetime)).append("\n");
    sb.append("    pkceMandatory: ").append(toIndentedString(pkceMandatory)).append("\n");
    sb.append("    pkceSupportPlain: ").append(toIndentedString(pkceSupportPlain)).append("\n");
    sb.append("    bypassClientCredentials: ").append(toIndentedString(bypassClientCredentials)).append("\n");
    sb.append("    tokenTypeExtension: ").append(toIndentedString(tokenTypeExtension)).append("\n");
    sb.append("    applicationScopes: ").append(toIndentedString(applicationScopes)).append("\n");
    sb.append("    extClientSecretDescription: ").append(toIndentedString(extClientSecretDescription)).append("\n");
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
