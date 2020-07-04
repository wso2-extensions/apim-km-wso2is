package wso2is.key.manager.userinfo.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;

import javax.xml.bind.annotation.*;




public class ClaimDTO   {
  
    private String uri = null;
    private String value = null;

  /**
   * Claim URI.
   **/
  public ClaimDTO uri(String uri) {
    this.uri = uri;
    return this;
  }

  
  @ApiModelProperty(example = "http://wso2.org/claims/givenname", value = "Claim URI.")
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
  public ClaimDTO value(String value) {
    this.value = value;
    return this;
  }

  
  @ApiModelProperty(example = "John", value = "Value for the claim.")
  @JsonProperty("value")
  public String getValue() {
    return value;
  }
  public void setValue(String value) {
    this.value = value;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ClaimDTO claim = (ClaimDTO) o;
    return Objects.equals(uri, claim.uri) &&
        Objects.equals(value, claim.value);
  }

  @Override
  public int hashCode() {
    return Objects.hash(uri, value);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClaimDTO {\n");
    
    sb.append("    uri: ").append(toIndentedString(uri)).append("\n");
    sb.append("    value: ").append(toIndentedString(value)).append("\n");
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

