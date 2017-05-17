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

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestTemplate;

/**
 * @author raman
 *
 */
public abstract class APIManagerService {

	protected RestTemplate rest = new RestTemplate();

	protected <T> T get(String token, String url, Class<T> resCls, Object ... params) {
		return rest.exchange(completeURL(url), HttpMethod.GET, secureEntity(token), resCls, params).getBody();
	}
	protected <T> T delete(String token, String url, Class<T> resCls, Object ... params) {
		return rest.exchange(completeURL(url), HttpMethod.GET, secureEntity(token), resCls, params).getBody();
	}
	protected <T, R> T post(String token, String url, Class<T> resCls, R in, Object ... params) {
		return rest.exchange(completeURL(url), HttpMethod.POST, secureEntity(in, token), resCls, params).getBody();
	}
	protected <T, R> T put(String token, String url, Class<T> resCls, R in, Object ... params) {
		return rest.exchange(completeURL(url), HttpMethod.POST, secureEntity(in, token), resCls, params).getBody();
	}
	protected <T> T get(String token, String url, ParameterizedTypeReference<T> resCls, Object ... params) {
		return rest.exchange(completeURL(url), HttpMethod.GET, secureEntity(token), resCls, params).getBody();
	}
	protected <T> T delete(String token, String url, ParameterizedTypeReference<T> resCls, Object ... params) {
		return rest.exchange(completeURL(url), HttpMethod.GET, secureEntity(token), resCls, params).getBody();
	}
	protected <T, R> T post(String token, String url, ParameterizedTypeReference<T> resCls, R in, Object ... params) {
		return rest.exchange(completeURL(url), HttpMethod.POST, secureEntity(in, token), resCls, params).getBody();
	}
	protected <T, R> T put(String token, String url, ParameterizedTypeReference<T> resCls, R in, Object ... params) {
		return rest.exchange(completeURL(url), HttpMethod.POST, secureEntity(in, token), resCls, params).getBody();
	}
	protected String completeURL(String url) {
		return endpoint() + url;
	}
	protected abstract String endpoint();
	

//	/**
//	 * @return
//	 */
//	protected String getBearerToken() {
//		return "Bearer " + getToken();
//	}
//
//	/**
//	 * @return
//	 */
//	protected String getToken() {
//		OAuth2Authentication auth = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
//		return ((OAuth2AuthenticationDetails) auth.getDetails()).getTokenValue();
//	}
//
//	protected String getUsername() {
//		OAuth2Authentication auth = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
//		return auth.getName();
//	}
	
	protected HttpEntity<String> secureEntity(String token) {
		HttpHeaders headers = new HttpHeaders();
    	headers.set("Authorization", "Bearer "  + token);
    	HttpEntity<String> entity = new HttpEntity<>(headers);
		return entity;
	}
	
	protected <T> HttpEntity<T> secureEntity(T value, String token) {
		HttpHeaders headers = new HttpHeaders();
    	headers.set("Authorization", "Bearer "  + token);
    	HttpEntity<T> entity = new HttpEntity<>(value, headers);
		return entity;
	}
}
