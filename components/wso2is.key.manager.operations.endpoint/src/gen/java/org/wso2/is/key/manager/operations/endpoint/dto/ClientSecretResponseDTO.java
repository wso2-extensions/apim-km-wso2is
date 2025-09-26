package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class ClientSecretResponseDTO   {
  
    private String id = null;
    private String description = null;
    private String clientSecret = null;
    private Long clientSecretExpiresAt = null;

  /**
   * Unique identifier for the secret
   **/
  public ClientSecretResponseDTO id(String id) {
    this.id = id;
    return this;
  }

  
  @ApiModelProperty(example = "sec_123456", value = "Unique identifier for the secret")
  @JsonProperty("id")
  public String getId() {
    return id;
  }
  public void setId(String id) {
    this.id = id;
  }

  /**
   * Human-readable label for the secret
   **/
  public ClientSecretResponseDTO description(String description) {
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
   * The actual secret string
   **/
  public ClientSecretResponseDTO clientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
    return this;
  }

  
  @ApiModelProperty(example = "s3cr3tV@lu3", value = "The actual secret string")
  @JsonProperty("client_secret")
  public String getClientSecret() {
    return clientSecret;
  }
  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  /**
   * expiry timestamp in seconds since epoch
   **/
  public ClientSecretResponseDTO clientSecretExpiresAt(Long clientSecretExpiresAt) {
    this.clientSecretExpiresAt = clientSecretExpiresAt;
    return this;
  }

  
  @ApiModelProperty(example = "1755756933", value = "expiry timestamp in seconds since epoch")
  @JsonProperty("client_secret_expires_at")
  public Long getClientSecretExpiresAt() {
    return clientSecretExpiresAt;
  }
  public void setClientSecretExpiresAt(Long clientSecretExpiresAt) {
    this.clientSecretExpiresAt = clientSecretExpiresAt;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ClientSecretResponseDTO clientSecretResponse = (ClientSecretResponseDTO) o;
    return Objects.equals(id, clientSecretResponse.id) &&
        Objects.equals(description, clientSecretResponse.description) &&
        Objects.equals(clientSecret, clientSecretResponse.clientSecret) &&
        Objects.equals(clientSecretExpiresAt, clientSecretResponse.clientSecretExpiresAt);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, description, clientSecret, clientSecretExpiresAt);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClientSecretResponseDTO {\n");
    
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    clientSecret: ").append(toIndentedString(clientSecret)).append("\n");
    sb.append("    clientSecretExpiresAt: ").append(toIndentedString(clientSecretExpiresAt)).append("\n");
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
