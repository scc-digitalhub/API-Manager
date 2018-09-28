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

import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.java.security.SSLProtocolSocketFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.http.ssl.TrustStrategy;
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
	
	public static void disableSSLValidator(ServiceClient client) {
		
		// Create a trust manager that does not validate certificate chains
	    final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
	            @Override
	            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
	                return null;
	            }

	            @Override
	            public void checkClientTrusted(X509Certificate[] certs, String authType) {
	            }

	            @Override
	            public void checkServerTrusted(X509Certificate[] certs, String authType) {
	            }
	        }
	    };
		TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;

	    // Install the all-trusting trust manager
	    try {
			SSLContext sc = org.apache.http.ssl.SSLContexts.custom()
			        .loadTrustMaterial(null, acceptingTrustStrategy)
			        .build();

	        sc.init(null, trustAllCerts, null);
	        SSLProtocolSocketFactory sslFactory = new SSLProtocolSocketFactory(sc);
	        Protocol prot = new Protocol("https", (ProtocolSocketFactory) sslFactory, 443);
	        client.getOptions().setProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER, prot);
	    } catch (Exception ex) {
	        // take action
	    }
	}
}
