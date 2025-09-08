package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class ClientSecretCreationRequestDTO   {
  
    private Integer expiresIn = null;
    private String description = null;

  /**
   * Expiry time in seconds
   **/
  public ClientSecretCreationRequestDTO expiresIn(Integer expiresIn) {
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
  public ClientSecretCreationRequestDTO description(String description) {
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


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ClientSecretCreationRequestDTO clientSecretCreationRequest = (ClientSecretCreationRequestDTO) o;
    return Objects.equals(expiresIn, clientSecretCreationRequest.expiresIn) &&
        Objects.equals(description, clientSecretCreationRequest.description);
  }

  @Override
  public int hashCode() {
    return Objects.hash(expiresIn, description);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClientSecretCreationRequestDTO {\n");
    
    sb.append("    expiresIn: ").append(toIndentedString(expiresIn)).append("\n");
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
