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

package it.smartcommunitylab.aac.wso2.model;

/**
 * @author raman
 *
 */
public class API extends APIInfo{

	private String apiDefinition, wsdlUri, thumbnailUri, visibility;
	private String[] visibleRoles, visibleTenants;
	
	private Boolean isDefaultVersion;
	private String responseCaching = "Disabled";
	private String[] transport = new String[]{ "http", "https"}, tiers = new String[] {"Unlimited"};
	private String endpointConfig;
	private String subscriptionAvailability;

	public String getApiDefinition() {
		return apiDefinition;
	}

	public void setApiDefinition(String apiDefinition) {
		this.apiDefinition = apiDefinition;
	}

	public String getWsdlUri() {
		return wsdlUri;
	}

	public void setWsdlUri(String wsdlUri) {
		this.wsdlUri = wsdlUri;
	}

	public String getThumbnailUri() {
		return thumbnailUri;
	}

	public void setThumbnailUri(String thumbnailUri) {
		this.thumbnailUri = thumbnailUri;
	}

	public String getVisibility() {
		return visibility;
	}

	public void setVisibility(String visibility) {
		this.visibility = visibility;
	}

	public String[] getVisibleRoles() {
		return visibleRoles;
	}

	public void setVisibleRoles(String[] visibleRoles) {
		this.visibleRoles = visibleRoles;
	}

	public String[] getVisibleTenants() {
		return visibleTenants;
	}

	public void setVisibleTenants(String[] visibleTenants) {
		this.visibleTenants = visibleTenants;
	}

	public String getResponseCaching() {
		return responseCaching;
	}

	public void setResponseCaching(String responseCaching) {
		this.responseCaching = responseCaching;
	}

	public String[] getTransport() {
		return transport;
	}

	public void setTransport(String[] transport) {
		this.transport = transport;
	}

	public String[] getTiers() {
		return tiers;
	}

	public void setTiers(String[] tiers) {
		this.tiers = tiers;
	}

	public String getEndpointConfig() {
		return endpointConfig;
	}

	public void setEndpointConfig(String endpointConfig) {
		this.endpointConfig = endpointConfig;
	}

	public Boolean getIsDefaultVersion() {
		return isDefaultVersion;
	}

	public void setIsDefaultVersion(Boolean isDefaultVersion) {
		this.isDefaultVersion = isDefaultVersion;
	}

	public String getSubscriptionAvailability() {
		return subscriptionAvailability;
	}

	public void setSubscriptionAvailability(String subscriptionAvailability) {
		this.subscriptionAvailability = subscriptionAvailability;
	}

}
