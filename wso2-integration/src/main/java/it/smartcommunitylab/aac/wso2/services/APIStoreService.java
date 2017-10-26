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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;

import it.smartcommunitylab.aac.wso2.model.App;
import it.smartcommunitylab.aac.wso2.model.DataList;
import it.smartcommunitylab.aac.wso2.model.Subscription;

/**
 * @author raman
 *
 */
public class APIStoreService extends APIManagerService {
	private static final int PAGE_SIZE = 25;
	@Value("${api.store.endpoint}")
	private String storeEndpoint;

	@Override
	protected String endpoint() {
		return storeEndpoint;
	}

	/**
	 * @param offset
	 * @param limit
	 * @param query
	 * @param token
	 * @return list of all {@link App} objects of the user associated to the specified token.
	 * The result is paginated and filtered.
	 */
	public DataList<App> getApps(Integer offset, Integer limit, String query, String token) 
	{
		ParameterizedTypeReference<DataList<App>> type = new ParameterizedTypeReference<DataList<App>>() {};
		return get(token, "/applications?offset={offset}&limit={limit}&query={query}", type, offset,limit,query);
	}

	/**
	 * @param appId
	 * @param token
	 * @return a specific {@link App} object.
	 */
	public String getApp(String appId, String token) {
		return get(token, "/applications/{appId}", String.class, appId);
	}
	
	public  DataList<Subscription> getSubscriptions(Integer offset, Integer limit, String appId, String token) {
		ParameterizedTypeReference<DataList<Subscription>> type = new ParameterizedTypeReference<DataList<Subscription>>() {};
		return get(token, "/subscriptions?offset={offset}&limit={limit}&applicationId={appId}", type, offset,limit,appId);
	}
	
	public void deleteSubscription(String subscriptionId, String token) {
		delete(token, "/subscriptions/{subscriptionId}", String.class, subscriptionId);
	}
	
	public App getApplication(String applicationName, String token) {
		int offset = 0;
		DataList<App> result = null;
		App app = null;
		
		do {
			result = getApps(offset, PAGE_SIZE, "", token);
			app = filterApplications(applicationName, result);
			offset += PAGE_SIZE;
		} while (result.getCount() == PAGE_SIZE && app == null);

		return app;
	}
	
	private App filterApplications(String applicationName, DataList<App> apps) {
		String parts[] = applicationName.split("_");
		
		return apps.getList().stream().filter(x -> x.getName().equals(parts[1]) && x.getSubscriber().equals(parts[0])).findFirst().orElse(null);
	}
	
	public List<Subscription> getSubscriptions(String applicationName, String token) {
		App app = getApplication(applicationName, token);
		if (app != null) {
			return getSubscriptionsByApplicationId(app.getApplicationId(), token);
		}
		return null;
	}
	
	private List<Subscription> getSubscriptionsByApplicationId(String appId, String token) {
		int offset = 0;
		List<Subscription> subscriptions = new ArrayList<Subscription>();
		DataList<Subscription> result = null;

		do {
			result = getSubscriptions(offset, PAGE_SIZE, appId, token);
			subscriptions.addAll(result.getList());
			offset += PAGE_SIZE;
		} while (result.getCount() == PAGE_SIZE);		
		
		
		return subscriptions;
	}	
	
	public void unsubscribe(String subscriptionId, String token) {
		delete(token, "/subscriptions/{subscriptionId}", String.class, subscriptionId);
	}		
	
	public void subscribe(String apiIdentifier, String applicationId, String token) {
		Map<String, String> map = new HashMap<String, String>();
		map.put("apiIdentifier", apiIdentifier);
		map.put("applicationId", applicationId);
		map.put("tier", "Unlimited");
		post(token, "/subscriptions/{subscriptionId}", Map.class, map, "");
	}		
	
}
