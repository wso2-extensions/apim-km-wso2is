package wso2is.key.manager.userinfo.endpoint.factories;

import wso2is.key.manager.userinfo.endpoint.ClaimsApiService;
import wso2is.key.manager.userinfo.endpoint.impl.ClaimsApiServiceImpl;

public class ClaimsApiServiceFactory {

   private final static ClaimsApiService service = new ClaimsApiServiceImpl();

   public static ClaimsApiService getClaimsApi()
   {
      return service;
   }
}
