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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;

import it.smartcommunitylab.aac.wso2.model.App;
import it.smartcommunitylab.aac.wso2.model.DataList;

/**
 * @author raman
 *
 */
public class APIStoreService extends APIManagerService {
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
}
