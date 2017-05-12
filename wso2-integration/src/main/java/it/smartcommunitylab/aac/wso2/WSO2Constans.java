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

package it.smartcommunitylab.aac.wso2;

/**
 * @author raman
 *
 */
public class WSO2Constans {

	public static final String ROLE_CREATOR = "Internal/creator";
	public static final String ROLE_PUBLISHER = "Internal/publisher";
	public static final String ROLE_SUBSCRIBER = "Internal/subscriber";
//	public static final String ROLE_IDENTITY = "Internal/identity";
	public static final String WSO2_CLAIM_EMAIL = "http://wso2.org/claims/emailaddress";
	public static final String WSO2_CLAIM_FIRST_NAME = "http://wso2.org/claims/givenname";
	public static final String WSO2_CLAIM_LAST_NAME = "http://wso2.org/claims/lastname";
	
	private static final String[] PUBLISHER = {ROLE_PUBLISHER, ROLE_CREATOR, ROLE_SUBSCRIBER};
	private static final String[] SUBSCRIBER = {ROLE_SUBSCRIBER}; //,ROLE_IDENTITY};
	
	public static String[] publisherRoles() {
		return PUBLISHER;
	}

	/**
	 * @return
	 */
	public static String[] subscriberRoles() {
		return SUBSCRIBER;
	}
}
