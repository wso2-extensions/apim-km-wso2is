package org.wso2.is.key.manager.operations.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.annotations.*;
import java.util.Objects;

public class ClaimRequestDTO   {
  
    private String username = null;
    private String accessToken = null;
    private String dialect = null;
    private String domain = null;

  /**
   **/
  public ClaimRequestDTO username(String username) {
    this.username = username;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("username")
  public String getUsername() {
    return username;
  }
  public void setUsername(String username) {
    this.username = username;
  }

  /**
   **/
  public ClaimRequestDTO accessToken(String accessToken) {
    this.accessToken = accessToken;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("accessToken")
  public String getAccessToken() {
    return accessToken;
  }
  public void setAccessToken(String accessToken) {
    this.accessToken = accessToken;
  }

  /**
   **/
  public ClaimRequestDTO dialect(String dialect) {
    this.dialect = dialect;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("dialect")
  public String getDialect() {
    return dialect;
  }
  public void setDialect(String dialect) {
    this.dialect = dialect;
  }

  /**
   **/
  public ClaimRequestDTO domain(String domain) {
    this.domain = domain;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("domain")
  public String getDomain() {
    return domain;
  }
  public void setDomain(String domain) {
    this.domain = domain;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ClaimRequestDTO claimRequest = (ClaimRequestDTO) o;
    return Objects.equals(username, claimRequest.username) &&
        Objects.equals(accessToken, claimRequest.accessToken) &&
        Objects.equals(dialect, claimRequest.dialect) &&
        Objects.equals(domain, claimRequest.domain);
  }

  @Override
  public int hashCode() {
    return Objects.hash(username, accessToken, dialect, domain);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClaimRequestDTO {\n");
    
    sb.append("    username: ").append(toIndentedString(username)).append("\n");
    sb.append("    accessToken: ").append(toIndentedString(accessToken)).append("\n");
    sb.append("    dialect: ").append(toIndentedString(dialect)).append("\n");
    sb.append("    domain: ").append(toIndentedString(domain)).append("\n");
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
