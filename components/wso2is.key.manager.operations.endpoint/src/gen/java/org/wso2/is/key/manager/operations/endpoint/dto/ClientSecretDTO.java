package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class ClientSecretDTO   {
  
    private String secretId = null;
    private String description = null;
    private String clientId = null;
    private String secretValue = null;
    private Long expiresAt = null;

  /**
   * Unique identifier for the secret
   **/
  public ClientSecretDTO secretId(String secretId) {
    this.secretId = secretId;
    return this;
  }

  
  @ApiModelProperty(example = "sec_123456", value = "Unique identifier for the secret")
  @JsonProperty("secretId")
  public String getSecretId() {
    return secretId;
  }
  public void setSecretId(String secretId) {
    this.secretId = secretId;
  }

  /**
   * Human-readable label for the secret
   **/
  public ClientSecretDTO description(String description) {
    this.description = description;
    return this;
  }

  
  @ApiModelProperty(example = "pizza application secret", value = "Human-readable label for the secret")
  @JsonProperty("description")
  public String getDescription() {
    return description;
  }
  public void setDescription(String description) {
    this.description = description;
  }

  /**
   * Client identifier of the application that owns this secret
   **/
  public ClientSecretDTO clientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  
  @ApiModelProperty(value = "Client identifier of the application that owns this secret")
  @JsonProperty("clientId")
  public String getClientId() {
    return clientId;
  }
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  /**
   * The actual secret string (only returned at creation time)
   **/
  public ClientSecretDTO secretValue(String secretValue) {
    this.secretValue = secretValue;
    return this;
  }

  
  @ApiModelProperty(example = "s3cr3tV@lu3", value = "The actual secret string (only returned at creation time)")
  @JsonProperty("secretValue")
  public String getSecretValue() {
    return secretValue;
  }
  public void setSecretValue(String secretValue) {
    this.secretValue = secretValue;
  }

  /**
   * expiry timestamp in seconds since epoch
   **/
  public ClientSecretDTO expiresAt(Long expiresAt) {
    this.expiresAt = expiresAt;
    return this;
  }

  
  @ApiModelProperty(example = "1755756933", value = "expiry timestamp in seconds since epoch")
  @JsonProperty("expiresAt")
  public Long getExpiresAt() {
    return expiresAt;
  }
  public void setExpiresAt(Long expiresAt) {
    this.expiresAt = expiresAt;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ClientSecretDTO clientSecret = (ClientSecretDTO) o;
    return Objects.equals(secretId, clientSecret.secretId) &&
        Objects.equals(description, clientSecret.description) &&
        Objects.equals(clientId, clientSecret.clientId) &&
        Objects.equals(secretValue, clientSecret.secretValue) &&
        Objects.equals(expiresAt, clientSecret.expiresAt);
  }

  @Override
  public int hashCode() {
    return Objects.hash(secretId, description, clientId, secretValue, expiresAt);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClientSecretDTO {\n");
    
    sb.append("    secretId: ").append(toIndentedString(secretId)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
    sb.append("    secretValue: ").append(toIndentedString(secretValue)).append("\n");
    sb.append("    expiresAt: ").append(toIndentedString(expiresAt)).append("\n");
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
