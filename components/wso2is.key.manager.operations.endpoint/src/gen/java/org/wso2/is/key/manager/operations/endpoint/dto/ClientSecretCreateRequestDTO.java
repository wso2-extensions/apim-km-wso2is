package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class ClientSecretCreateRequestDTO   {
  
    private Integer expiryTime = null;
    private String description = null;

  /**
   * Expiry time in seconds (relative to now).
   **/
  public ClientSecretCreateRequestDTO expiryTime(Integer expiryTime) {
    this.expiryTime = expiryTime;
    return this;
  }

  
  @ApiModelProperty(value = "Expiry time in seconds (relative to now).")
  @JsonProperty("expiryTime")
  public Integer getExpiryTime() {
    return expiryTime;
  }
  public void setExpiryTime(Integer expiryTime) {
    this.expiryTime = expiryTime;
  }

  /**
   * A human-readable label for this secret.
   **/
  public ClientSecretCreateRequestDTO description(String description) {
    this.description = description;
    return this;
  }

  
  @ApiModelProperty(value = "A human-readable label for this secret.")
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
    ClientSecretCreateRequestDTO clientSecretCreateRequest = (ClientSecretCreateRequestDTO) o;
    return Objects.equals(expiryTime, clientSecretCreateRequest.expiryTime) &&
        Objects.equals(description, clientSecretCreateRequest.description);
  }

  @Override
  public int hashCode() {
    return Objects.hash(expiryTime, description);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClientSecretCreateRequestDTO {\n");
    
    sb.append("    expiryTime: ").append(toIndentedString(expiryTime)).append("\n");
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
