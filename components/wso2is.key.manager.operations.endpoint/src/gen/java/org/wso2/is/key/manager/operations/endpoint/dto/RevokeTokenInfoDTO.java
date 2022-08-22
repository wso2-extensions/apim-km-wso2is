package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;



public class RevokeTokenInfoDTO   {
  
    private String token = null;
    private String consumerKey = null;

  /**
   * JWT token that is needed to revoke 
   **/
  public RevokeTokenInfoDTO token(String token) {
    this.token = token;
    return this;
  }

  
  @ApiModelProperty(value = "JWT token that is needed to revoke ")
  @JsonProperty("token")
  public String getToken() {
    return token;
  }
  public void setToken(String token) {
    this.token = token;
  }

  /**
   * Consumer key of the user 
   **/
  public RevokeTokenInfoDTO consumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
    return this;
  }

  
  @ApiModelProperty(value = "Consumer key of the user ")
  @JsonProperty("consumer_key")
  public String getConsumerKey() {
    return consumerKey;
  }
  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RevokeTokenInfoDTO revokeTokenInfo = (RevokeTokenInfoDTO) o;
    return Objects.equals(token, revokeTokenInfo.token) &&
        Objects.equals(consumerKey, revokeTokenInfo.consumerKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(token, consumerKey);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RevokeTokenInfoDTO {\n");
    
    sb.append("    token: ").append(toIndentedString(token)).append("\n");
    sb.append("    consumerKey: ").append(toIndentedString(consumerKey)).append("\n");
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
