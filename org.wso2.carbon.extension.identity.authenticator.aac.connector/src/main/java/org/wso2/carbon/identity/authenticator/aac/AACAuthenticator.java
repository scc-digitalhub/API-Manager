/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.aac;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementServiceImpl;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of AAC
 */
public class AACAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(AACAuthenticator.class);

    /**
     * Get AAC authorization endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
    }

    /**
     * Get AAC token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
    }

    /**
     * Check ID token in AAC OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return AACAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return AACAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get the scope
     */
    public String getScope(String scope, Map<String, String> authenticatorProperties) {
        scope = authenticatorProperties.get(AACAuthenticatorConstants.SCOPE);
        if (StringUtils.isEmpty(scope)) {
            scope = AACAuthenticatorConstants.USER_SCOPE;
        }
        return scope;
    }


    /**
     * Process the response of first call
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
            String callbackUrl = getCallbackUrl(authenticatorProperties);
            

            OAuthAuthzResponse authorizationResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authorizationResponse.getCode();

            OAuthClientRequest accessRequest =
                    getAccessRequest(tokenEndPoint, clientId, code, clientSecret, callbackUrl);
            AACOAuthClient oAuthClient = new AACOAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessRequest);
            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }
            String userInfoUrl = getUserInfoEndpoint(oAuthResponse, authenticatorProperties);
            String token = sendRequest(userInfoUrl, accessToken);

            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }

            AuthenticatedUser authenticatedUserObj;
            Map<ClaimMapping, String> claims;
            authenticatedUserObj = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(JSONUtils.parseJSON(token)
                            .get(AACAuthenticatorConstants.USER_ID).toString());
            authenticatedUserObj.setAuthenticatedSubjectIdentifier(JSONUtils.parseJSON(token)
                    .get(AACAuthenticatorConstants.USER_ID).toString());
            claims = getSubjectAttributes(oAuthResponse, authenticatorProperties);
            log.error("starting entity provisioning in processAuth");
            String tenantDomain = "testing.com";//JSONUtils.parseJSON(token).get("tenant_name").toString();
            log.error(claims.toString());
            authenticatedUserObj.setTenantDomain(tenantDomain);
            authenticatedUserObj.setUserAttributes(claims);
            context.setSubject(authenticatedUserObj);
            context.setTenantDomain(tenantDomain);
            context.setProperty("postAuthenticationRedirectionTriggered", false);
            AACProvisioningHandler provHandler = AACProvisioningHandler.getInstance();
            List<String> roles = new ArrayList<>();
            roles.add("Internal/publisher");
            roles.add("Internal/creator");
            roles.add("Internal/subscriber");
            roles.add("Internal/everyone");
            roles.add("admin");
            Map<String, String> claimMap = getSubjectAttr(oAuthResponse, authenticatorProperties);
            String subject = JSONUtils.parseJSON(token)
                    .get(AACAuthenticatorConstants.USER_ID).toString() + "@" + tenantDomain;
            provHandler.handle(roles, subject, claimMap, "As in username", tenantDomain);
        } catch ( IOException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        } catch (OAuthProblemException e) {
        	throw new AuthenticationFailedException("Authentication process failed", e);
		} catch (FrameworkException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    protected Map<ClaimMapping, String> getSubjectAttributes(OAuthClientResponse token,
            Map<String, String> authenticatorProperties) {

	Map<ClaimMapping, String> claims = new HashMap<>();
	try {
	
		String accessToken = token.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
		String url = getUserInfoEndpoint(token, authenticatorProperties);
		
		String json = sendRequest(url, accessToken);
		
		if (StringUtils.isBlank(json)) {
			if(log.isDebugEnabled()) {
			log	.debug("Unable to fetch user claims. Proceeding without user claims");
			}
			return claims;
		}
		
		Map<String, Object> jsonObject = JSONUtils.parseJSON(json);
		
		for (Map.Entry<String, Object> data : jsonObject.entrySet()) {
			String key = data.getKey();
			switch(key) {
//				case "email":
//					claims.put(ClaimMapping.build("http://wso2.org/claims/emailaddress", key, null, false), jsonObject.get(key).toString());
//					break;
				case "email":
					claims.put(ClaimMapping.build("http://wso2.org/claims/username", key, null, false), jsonObject.get(key).toString());
					break;
				case "given_name":
					claims.put(ClaimMapping.build("http://wso2.org/claims/givenname", key, null, false), jsonObject.get(key).toString());
					break;
				case "name":
					claims.put(ClaimMapping.build("http://wso2.org/claims/fullname", key, null, false), jsonObject.get(key).toString());
					break;
//				case "last_name":
//					claims.put(ClaimMapping.build("http://wso2.org/claims/lastname", key, null, false), jsonObject.get(key).toString());
//					break;
				case "preferred_username":
					claims.put(ClaimMapping.build("http://wso2.org/claims/emailaddress", key, null, false), jsonObject.get(key).toString());
					break;
				case "family_name"://groups
					claims.put(ClaimMapping.build("http://wso2.org/claims/lastname", key,null, false), jsonObject.get(key).toString());
					break;
			}
			log.info("claimsss: " + key + " " + jsonObject.get(key).toString());
//			claims.put(ClaimMapping.build(key, key, null, false), jsonObject.get(key).toString());
			
			if (log.isDebugEnabled() ) {
				log.debug("Adding claims from end-point data mapping : " + key + " - " +
				jsonObject.get(key).toString());
			}
		}
		claims.put(ClaimMapping.build("http://wso2.org/claims/role", "groups", null, false), "Internal/publisher,Internal/everyone,admin");
	} catch (Exception e) {
		log	.error("Error occurred while accessing user info endpoint", e);
	}
	
	return claims;
}
    
    protected Map<String, String> getSubjectAttr(OAuthClientResponse token, Map<String, String> authenticatorProperties) {

	Map<String, String> claims = new HashMap<>();
	
	try {
	
		String accessToken = token.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);
		String url = getUserInfoEndpoint(token, authenticatorProperties);
		
		String json = sendRequest(url, accessToken);
		
		if (StringUtils.isBlank(json)) {
			if(log.isDebugEnabled()) {
			log	.debug("Unable to fetch user claims. Proceeding without user claims");
			}
			return claims;
		}
		
		Map<String, Object> jsonObject = JSONUtils.parseJSON(json);
		
		for (Map.Entry<String, Object> data : jsonObject.entrySet()) {
		
			String key = data.getKey();
			switch(key) {
				case "email":
					claims.put("http://wso2.org/claims/username", jsonObject.get(key).toString());
					break;
				case "given_name":
					claims.put("http://wso2.org/claims/givenname", jsonObject.get(key).toString());
					break;
				case "name":
					claims.put("http://wso2.org/claims/fullname", jsonObject.get(key).toString());
					break;
//				case "last_name":
//					claims.put("http://wso2.org/claims/lastname", jsonObject.get(key).toString());
//					break;
				case "preferred_username":
					claims.put("http://wso2.org/claims/emailaddress", jsonObject.get(key).toString());
					break;
				case "family_name"://groups
					claims.put("http://wso2.org/claims/lastname", jsonObject.get(key).toString());
					break;
			}
//			claims.put(key, jsonObject.get(key).toString());
			
			if (log.isDebugEnabled() ) {
				log.debug("Adding claims from end-point data mapping : " + key + " - " +
				jsonObject.get(key).toString());
			}
		}
		claims.put("http://wso2.org/claims/role", "Internal/publisher,Internal/everyone,admin");
	
	} catch (Exception e) {
		log	.error("Error occurred while accessing user info endpoint", e);
	}
	
	return claims;
}
    
    private OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {
        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch ( OAuthProblemException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
        	throw new AuthenticationFailedException(e.getMessage(), e);
		}
        return oAuthResponse;
    }

    private OAuthClientRequest getAccessRequest(String tokenEndPoint, String clientId, String code, String clientSecret,
                                                String callbackurl) throws AuthenticationFailedException {
        OAuthClientRequest accessRequest;
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientId)
                    .setClientSecret(clientSecret).setRedirectURI(callbackurl).setCode(code)
                    .buildBodyMessage();
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return accessRequest;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter AAC IDP client identifier value");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter AAC IDP client secret value");
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property scope = new Property();
        scope.setName(AACAuthenticatorConstants.SCOPE);
        scope.setDisplayName("Scope");
        scope.setRequired(false);
        scope.setDescription("Enter scope for the user access");
        scope.setDisplayOrder(3);
        configProperties.add(scope);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter value corresponding to callback url.");
        callbackUrl.setDisplayOrder(4);
        configProperties.add(callbackUrl);
        
        Property authServerEP = new Property();
        authServerEP.setDisplayName("Authorization Server Endpoint");
        authServerEP.setName(IdentityApplicationConstants.OAuth2.OAUTH2_AUTHZ_URL);
        authServerEP.setDescription("Enter value corresponding to authorization server url.");
        authServerEP.setDisplayOrder(5);
        configProperties.add(authServerEP);
        
        Property tokenUrl = new Property();
        tokenUrl.setDisplayName("Token URL");
        tokenUrl.setName(IdentityApplicationConstants.OAuth2.OAUTH2_TOKEN_URL);
        tokenUrl.setDescription("Enter value corresponding to token url.");
        tokenUrl.setDisplayOrder(6);
        configProperties.add(tokenUrl);
        
        Property userInfoEP = new Property();
        userInfoEP.setDisplayName("User Info URL");
        userInfoEP.setName(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
        userInfoEP.setDescription("Enter value corresponding to user Info url.");
        userInfoEP.setDisplayOrder(7);
        configProperties.add(userInfoEP);

        return configProperties;
    }

    /**
     * Request user claims from user info endpoint.
     *
     * @param url         User info endpoint.
     * @param accessToken Access token.
     * @return Response string.
     * @throws IOException
     */
    protected String sendRequest(String url, String accessToken)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Claim URL: " + url);
        }

        if (url == null) {
            return StringUtils.EMPTY;
        }

        URL obj = new URL(url);
        HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();
        urlConnection.setRequestMethod("GET");
        urlConnection.setRequestProperty("Authorization", "Bearer " + accessToken);
        BufferedReader reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
        StringBuilder builder = new StringBuilder();
        String inputLine = reader.readLine();
        while (inputLine != null) {
            builder.append(inputLine).append("\n");
            inputLine = reader.readLine();
        }
        reader.close();
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            log.info("response: " + builder.toString());
        }
        return builder.toString();
    }
}

