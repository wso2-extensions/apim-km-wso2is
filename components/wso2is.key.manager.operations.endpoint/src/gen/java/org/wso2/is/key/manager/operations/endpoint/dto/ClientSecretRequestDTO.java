package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class ClientSecretRequestDTO   {
  
    private Integer expiresIn = null;
    private String description = null;
    private String clientSecret = null;

  /**
   * Expiry time in seconds
   **/
  public ClientSecretRequestDTO expiresIn(Integer expiresIn) {
    this.expiresIn = expiresIn;
    return this;
  }

  
  @ApiModelProperty(example = "86400", value = "Expiry time in seconds")
  @JsonProperty("expires_in")
  public Integer getExpiresIn() {
    return expiresIn;
  }
  public void setExpiresIn(Integer expiresIn) {
    this.expiresIn = expiresIn;
  }

  /**
   * A human-readable label for this secret
   **/
  public ClientSecretRequestDTO description(String description) {
    this.description = description;
    return this;
  }

  
  @ApiModelProperty(example = "pizza application secret", value = "A human-readable label for this secret")
  @JsonProperty("description")
  public String getDescription() {
    return description;
  }
  public void setDescription(String description) {
    this.description = description;
  }

  /**
   * Optional client secret value to restore. If not provided, a new secret is auto-generated.
   **/
  public ClientSecretRequestDTO clientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
    return this;
  }

  
  @ApiModelProperty(value = "Optional client secret value to restore. If not provided, a new secret is auto-generated.")
  @JsonProperty("client_secret")
  public String getClientSecret() {
    return clientSecret;
  }
  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ClientSecretRequestDTO clientSecretRequest = (ClientSecretRequestDTO) o;
    return Objects.equals(expiresIn, clientSecretRequest.expiresIn) &&
        Objects.equals(description, clientSecretRequest.description) &&
        Objects.equals(clientSecret, clientSecretRequest.clientSecret);
  }

  @Override
  public int hashCode() {
    return Objects.hash(expiresIn, description, clientSecret);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClientSecretRequestDTO {\n");
    
    sb.append("    expiresIn: ").append(toIndentedString(expiresIn)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    clientSecret: ").append(toIndentedString(clientSecret)).append("\n");
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
