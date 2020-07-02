package wso2is.key.manager.userinfo.endpoint.dto;


import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;





@ApiModel(description = "")
public class ClaimRequestDTO  {
  
  
  
  private String accessToken = null;
  
  
  private String authorizationCode = null;
  
  
  private String dialect = null;

  
  /**
   **/
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
  @ApiModelProperty(value = "")
  @JsonProperty("authorizationCode")
  public String getAuthorizationCode() {
    return authorizationCode;
  }
  public void setAuthorizationCode(String authorizationCode) {
    this.authorizationCode = authorizationCode;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("dialect")
  public String getDialect() {
    return dialect;
  }
  public void setDialect(String dialect) {
    this.dialect = dialect;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClaimRequestDTO {\n");
    
    sb.append("  accessToken: ").append(accessToken).append("\n");
    sb.append("  authorizationCode: ").append(authorizationCode).append("\n");
    sb.append("  dialect: ").append(dialect).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
