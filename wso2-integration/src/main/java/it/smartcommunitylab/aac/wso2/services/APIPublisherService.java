/*******************************************************************************
 * Copyright 2015 Fondazione Bruno Kessler
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 ******************************************************************************/

package it.smartcommunitylab.aac.wso2.services;

import it.smartcommunitylab.aac.wso2.model.API;
import it.smartcommunitylab.aac.wso2.model.APIInfo;
import it.smartcommunitylab.aac.wso2.model.App;
import it.smartcommunitylab.aac.wso2.model.DataList;
import it.smartcommunitylab.aac.wso2.model.RoleModel;
import it.smartcommunitylab.aac.wso2.model.Subscription;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.axis2.AxisFault;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ResponseBody;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceExceptionException;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceUserStoreExceptionException;

/**
 * @author raman
 *
 */
public class APIPublisherService extends APIManagerService {
	
	private static final Logger logger = LoggerFactory.getLogger(APIPublisherService.class); 
	
	@Value("${api.publisher.endpoint}")
	private String publisherEndpoint;

	@Autowired
	private UserManagementService umService;
	
	@Override
	protected String endpoint() {
		return publisherEndpoint;
	}

	/**
	 * 
	 * @param apiId
	 * @param offset
	 * @param limit
	 * @return List of all {@link Subscription}s to the specified API of the developer associated to the token, paginated.
	 */
	public DataList<Subscription> getSubscriptions(String apiId, String apiDomain, Integer offset, Integer limit, String token) {
		API api = get(token, "/apis/{apiId}", API.class, apiId);
		Set<String> roles = getAPIRoles(api);
		
		ParameterizedTypeReference<DataList<Subscription>> type = new ParameterizedTypeReference<DataList<Subscription>>() {};
		DataList<Subscription> result = get(token, "/subscriptions?apiId={apiId}&limit={limit}&offset={offset}", type, apiId, limit, offset);
		
		result.getList().forEach(s -> {
			App app = get(token, "/applications/{appId}", App.class, s.getApplicationId());
			s.setSubscriber(Utils.getUserNormalizedName(app.getSubscriber()));
			s.setAppName(app.getName());
			
			try {
				List<String>  allRoles = new ArrayList<>();
				for (String role : roles) {
					if (umService.isUserInRole(s.getSubscriber(), role, apiDomain)) {
						allRoles.add(role);
					}
				}
				s.setRoles(allRoles);
			} catch (Exception e) {
				logger.error("Error retrieving roles of the user "+ s.getSubscriber(), e);
			}
			
		});
		
		return result;
	}

	/**
	 * 
	 * @param apiId
	 * @param user the user to check the roles
	 * @param domain the domain of the user
	 * @param token the token of the API developer
	 * @return List of roles the specified user has with respect to the specified API.
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 * @throws TenantMgtAdminServiceExceptionException 
	 */
	public List<String> getUserAPIRoles(String apiId, String apiDomain, String user, String domain, String token) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException, TenantMgtAdminServiceExceptionException {
		API api = get(token, "/apis/{apiId}", API.class, apiId);
		Set<String> roles = getAPIRoles(api);
		List<String>  allRoles = new ArrayList<>();
		for (String role : roles) {
			if (umService.isUserInRole(user, role, apiDomain)) {
				allRoles.add(role);
			}
		}
		return allRoles;
	}
	
	/**
	 * @param api
	 * @return all roles associated with the API
	 */
	private Set<String> getAPIRoles(API api) {
		JSONObject obj = new JSONObject(api.getApiDefinition());
		Set<String> set = new HashSet<>();
		if (obj.has("x-wso2-security")) {
			obj = obj.getJSONObject("x-wso2-security");
			if (obj.has("apim")) {
				obj = obj.getJSONObject("apim");
				if (obj.has("x-wso2-scopes")) {
					JSONArray array = obj.getJSONArray("x-wso2-scopes");
					for (int i = 0; i < array.length(); i++) {
						obj = array.getJSONObject(i);
						if (obj.has("roles")) {
							set.addAll(StringUtils.commaDelimitedListToSet(obj.getString("roles")));
						}
					}
				}
			}
		}
		return set;
	}


	/**
	 * List of all APIs (paginated) owned by the developer associated to the specified token. If
	 * query string is specified, the full text search on the query.
	 * @param offset
	 * @param limit
	 * @param query
	 * @param token
	 * @return
	 */
	public  DataList<APIInfo> getAPIs(Integer offset, Integer limit, String query, String token) {
		ParameterizedTypeReference<DataList<APIInfo>> type = new ParameterizedTypeReference<DataList<APIInfo>>() {};
		return get(token, "/apis?offset={offset}&limit={limit}&query={query}", type, offset,limit,query);
	}
	
	/**
	 * 
	 * @param apiId
	 * @param token
	 * @return the specified {@link API} corresponding to the passed apiId.
	 */
	public API getAPI(String apiId, String token) {
		API api = get(token, "/apis/{apiId}", API.class, apiId);
		
		if (api.getThumbnailUri() != null) {
			api.setThumbnailUri("/rest"+api.getThumbnailUri());
		}
		return api;
	}
	
	/**
	 * 
	 * @param apiId
	 * @param token
	 * @return binary stream of the API thumbnail
	 */
	public byte[] getAPIThumbnail(String apiId, String token) {
		API api = get(token, "/apis/{apiId}", API.class, apiId);
		if (api.getThumbnailUri() != null) return get(token, "/apis/{apiId}/thumbnail", byte[].class, apiId);
		return null;
	}

	/**
	 * Update user roles with respect to the specified API.
	 * @param apiId
	 * @param roleModel
	 * @param username
	 * @param domain
	 * @param token
	 * @return
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws TenantMgtAdminServiceExceptionException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 */
	public @ResponseBody List<String> updateRoles(String apiId, RoleModel roleModel, String username, String domain, String token) throws AxisFault, RemoteException, TenantMgtAdminServiceExceptionException, RemoteUserStoreManagerServiceUserStoreExceptionException 
	{
		umService.updateRoles(roleModel, username, domain);
		return getUserAPIRoles(apiId, username, domain, token);
	}
}
