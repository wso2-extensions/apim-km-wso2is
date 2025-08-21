package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import java.time.OffsetDateTime;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class SecretDTO   {
  
    private String secretId = null;
    private String clientId = null;
    private String secretValue = null;
    private OffsetDateTime createdAt = null;
    private OffsetDateTime expiresAt = null;
    private OffsetDateTime revokedAt = null;
    private String description = null;

  /**
   * Unique identifier for the secret
   **/
  public SecretDTO secretId(String secretId) {
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
   * Client identifier that owns this secret
   **/
  public SecretDTO clientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  
  @ApiModelProperty(value = "Client identifier that owns this secret")
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
  public SecretDTO secretValue(String secretValue) {
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
   * When the secret was created
   **/
  public SecretDTO createdAt(OffsetDateTime createdAt) {
    this.createdAt = createdAt;
    return this;
  }

  
  @ApiModelProperty(value = "When the secret was created")
  @JsonProperty("createdAt")
  public OffsetDateTime getCreatedAt() {
    return createdAt;
  }
  public void setCreatedAt(OffsetDateTime createdAt) {
    this.createdAt = createdAt;
  }

  /**
   * Expiry timestamp (if applicable)
   **/
  public SecretDTO expiresAt(OffsetDateTime expiresAt) {
    this.expiresAt = expiresAt;
    return this;
  }

  
  @ApiModelProperty(value = "Expiry timestamp (if applicable)")
  @JsonProperty("expiresAt")
  public OffsetDateTime getExpiresAt() {
    return expiresAt;
  }
  public void setExpiresAt(OffsetDateTime expiresAt) {
    this.expiresAt = expiresAt;
  }

  /**
   * When the secret was revoked (if applicable)
   **/
  public SecretDTO revokedAt(OffsetDateTime revokedAt) {
    this.revokedAt = revokedAt;
    return this;
  }

  
  @ApiModelProperty(value = "When the secret was revoked (if applicable)")
  @JsonProperty("revokedAt")
  public OffsetDateTime getRevokedAt() {
    return revokedAt;
  }
  public void setRevokedAt(OffsetDateTime revokedAt) {
    this.revokedAt = revokedAt;
  }

  /**
   * Human-readable label for the secret
   **/
  public SecretDTO description(String description) {
    this.description = description;
    return this;
  }

  
  @ApiModelProperty(value = "Human-readable label for the secret")
  @JsonProperty("description")
  public String getDescription() {
    return description;
  }
  public void setDescription(String description) {
    this.description = description;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SecretDTO secret = (SecretDTO) o;
    return Objects.equals(secretId, secret.secretId) &&
        Objects.equals(clientId, secret.clientId) &&
        Objects.equals(secretValue, secret.secretValue) &&
        Objects.equals(createdAt, secret.createdAt) &&
        Objects.equals(expiresAt, secret.expiresAt) &&
        Objects.equals(revokedAt, secret.revokedAt) &&
        Objects.equals(description, secret.description);
  }

  @Override
  public int hashCode() {
    return Objects.hash(secretId, clientId, secretValue, createdAt, expiresAt, revokedAt, description);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SecretDTO {\n");
    
    sb.append("    secretId: ").append(toIndentedString(secretId)).append("\n");
    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
    sb.append("    secretValue: ").append(toIndentedString(secretValue)).append("\n");
    sb.append("    createdAt: ").append(toIndentedString(createdAt)).append("\n");
    sb.append("    expiresAt: ").append(toIndentedString(expiresAt)).append("\n");
    sb.append("    revokedAt: ").append(toIndentedString(revokedAt)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
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
