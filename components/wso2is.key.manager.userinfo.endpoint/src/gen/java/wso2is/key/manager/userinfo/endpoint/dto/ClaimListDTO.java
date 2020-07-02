package wso2is.key.manager.userinfo.endpoint.dto;

import java.util.ArrayList;
import java.util.List;
import wso2is.key.manager.userinfo.endpoint.dto.ClaimDTO;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;





@ApiModel(description = "")
public class ClaimListDTO  {
  
  
  
  private Integer count = null;
  
  
  private List<ClaimDTO> list = new ArrayList<ClaimDTO>();

  
  /**
   * Number of claims returned.\n
   **/
  @ApiModelProperty(value = "Number of claims returned.\n")
  @JsonProperty("count")
  public Integer getCount() {
    return count;
  }
  public void setCount(Integer count) {
    this.count = count;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("list")
  public List<ClaimDTO> getList() {
    return list;
  }
  public void setList(List<ClaimDTO> list) {
    this.list = list;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ClaimListDTO {\n");
    
    sb.append("  count: ").append(count).append("\n");
    sb.append("  list: ").append(list).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
