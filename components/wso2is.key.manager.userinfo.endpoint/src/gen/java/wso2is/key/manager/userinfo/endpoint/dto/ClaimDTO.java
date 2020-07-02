package wso2is.key.manager.userinfo.endpoint.dto;


import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;





@ApiModel(description = "")
public class ClaimDTO  {
  
  
  
  private String uri = null;
  
  
  private String value = null;

  
  /**
   * Claim URI.
   **/
  @ApiModelProperty(value = "Claim URI.")
  @JsonProperty("uri")
  public String getUri() {
    return uri;
  }
  public void setUri(String uri) {
    this.uri = uri;
  }

  
  /**
   * Value for the claim.
   **/
  @ApiModelProperty(value = "Value for the claim.")
  @JsonProperty("value")
  public String getValue() {
    return value;
  }
  public void setValue(String value) {
    this.value = value;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClaimDTO {\n");
    
    sb.append("  uri: ").append(uri).append("\n");
    sb.append("  value: ").append(value).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
