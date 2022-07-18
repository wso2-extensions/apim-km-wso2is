package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class RevokeTokenDTO   {
  
    private String token = null;
    private String clientId = null;

  /**
   * Id of the revoking token 
   **/
  public RevokeTokenDTO token(String token) {
    this.token = token;
    return this;
  }

  
  @ApiModelProperty(value = "Id of the revoking token ")
  @JsonProperty("token")
  public String getToken() {
    return token;
  }
  public void setToken(String token) {
    this.token = token;
  }

  /**
   * Id of the user 
   **/
  public RevokeTokenDTO clientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  
  @ApiModelProperty(value = "Id of the user ")
  @JsonProperty("client_id")
  public String getClientId() {
    return clientId;
  }
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RevokeTokenDTO revokeToken = (RevokeTokenDTO) o;
    return Objects.equals(token, revokeToken.token) &&
        Objects.equals(clientId, revokeToken.clientId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(token, clientId);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RevokeTokenDTO {\n");
    
    sb.append("    token: ").append(toIndentedString(token)).append("\n");
    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
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
