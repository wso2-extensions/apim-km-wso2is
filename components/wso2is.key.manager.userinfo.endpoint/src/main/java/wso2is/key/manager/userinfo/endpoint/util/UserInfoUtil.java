/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package wso2is.key.manager.userinfo.endpoint.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import wso2is.key.manager.userinfo.endpoint.dto.ClaimDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ClaimListDTO;
import wso2is.key.manager.userinfo.endpoint.dto.ErrorDTO;

public class UserInfoUtil {
    
    public static ErrorDTO getError(String code, String message, String description) {
        ErrorDTO errorDTO = new ErrorDTO();
        errorDTO.setCode(code);
        errorDTO.setMessage(message);
        errorDTO.setDescription(description);
        return errorDTO;
    }
    
    public static ClaimListDTO getListDTOfromClaimsMap(Map<String, String> claims) {
        ClaimListDTO listDto = new ClaimListDTO();
        List<ClaimDTO> list = new ArrayList<ClaimDTO>();
        listDto.setCount(claims.size());
        for (String claim : claims.keySet()) {
            ClaimDTO dto = new ClaimDTO();
            dto.setUri(claim);
            dto.setValue(claims.get(claim));
            list.add(dto);
        }
        listDto.setList(list);
        return listDto;
    }

}
