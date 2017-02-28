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

import org.wso2.carbon.um.ws.api.stub.ClaimValue;

/**
 * @author raman
 *
 */
public class Utils {

	private static final String PROD_SP = "%s_%s_PRODUCTION";
	private static final String SAND_SP = "%s_%s_SANDBOX";
	
	private static final String SUPER_TENANT = "carbon.super";
	
//	public static String getUserLocalName() {
//		String principal = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//		return getLocalName(principal);
//	}
//	public static String getUserFullName() {
//		String principal = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//		return principal;
//	}
	public static String getUserTenantName(String userNameWithTenant) {
		return getTenantName(userNameWithTenant);
	}
	public static String getUserNormalizedName(String user) {
		if (user.endsWith("@"+SUPER_TENANT)) return user.substring(0,  user.lastIndexOf('@'));
		return user;
	}
	
	public static String getUserNameAtSuperTenant(String username) {
		return username + "@" + SUPER_TENANT;
	}
	
	public static String getUserNameAtTenant(String username, String tenantName) {
		return username + "@" + tenantName;
	}
	
	
	/**
	 * @param principal
	 * @return
	 */
	private static String getTenantName(String principal) {
		if (principal.indexOf('@') > 0) return principal.substring(principal.lastIndexOf('@')+1);
		return SUPER_TENANT;
	}

	/**
	 * @param appName
	 * @return
	 */
	public static String getProductionSP(String appName, String username) {
		return String.format(PROD_SP, username, appName);
	}
	
	/**
	 * @param appName
	 * @return
	 */
	public static String getSandboxSP(String appName, String username) {
		return String.format(SAND_SP, username, appName);
	}

	public static ClaimValue createClaimValue(String uri, String value) {
		ClaimValue cv = new ClaimValue();
		cv.setClaimURI(uri);
		cv.setValue(value);
		return cv;
	}
	
}
