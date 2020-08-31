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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.validators.jwt.JWKSBasedJWTValidator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;
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
     * Get AAC role endpoint.
     */
    protected String getJWKEndpoint(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(AACAuthenticatorConstants.JWK_ENDPOINT);
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
            JWTClaimsSet claimSet = verifyToken(accessToken, getJWKEndpoint(authenticatorProperties));
            if (claimSet == null) {
                throw new AuthenticationFailedException("JWT is empty or null");
            }
            Map<String, Object> userInfo = claimSet.getClaims();
            
            AuthenticatedUser authenticatedUserObj;
            Map<ClaimMapping, String> claims;
            authenticatedUserObj = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(userInfo.get(AACAuthenticatorConstants.USER_ID).toString());
            authenticatedUserObj.setAuthenticatedSubjectIdentifier(userInfo.get(AACAuthenticatorConstants.USER_ID).toString());
            claims = getSubjectAttributes(userInfo);
            if(userInfo.get("space") == null) {
            	log.error("Space parameter of the jwt token is missing. Try to filter the proper spaces");
            	 throw new AuthenticationFailedException("Space parameter of the jwt token is missing. Try to filter the proper spaces");
            }
            String tenantDomain = userInfo.get("space").toString();
            authenticatedUserObj.setTenantDomain(tenantDomain);
            authenticatedUserObj.setUserAttributes(claims);
            context.setSubject(authenticatedUserObj);
            context.setTenantDomain(tenantDomain);
            context.setProperty("postAuthenticationRedirectionTriggered", false);
            context.setForceAuthenticate(true);
            
            AACProvisioningHandler provHandler = AACProvisioningHandler.getInstance();
            List<String> roles = new ArrayList<>();
            roles.add("Internal/publisher");
            roles.add("Internal/subscriber");
            roles.add("Internal/everyone");
            if(isProvider(userInfo.get("roles"))) {
            	roles.add("Internal/creator");
	            roles.add("admin");
            }
            Map<String, String> claimMap = getSubjectAttr(userInfo);
            String subject = userInfo.get(AACAuthenticatorConstants.USER_ID).toString() + "@" + tenantDomain;         

            // Retrieve session information from cache.
//            SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(context.getCallerSessionKey());
//            // Remove federated authentication session details from the database.
//            if (sessionContext != null && StringUtils.isNotBlank(context.getSessionIdentifier()) &&
//                    sessionContext.getSessionAuthHistory().getHistory() != null) {
//                for (AuthHistory authHistory : sessionContext.getSessionAuthHistory().getHistory()) {
//                    if ("AACAuthenticator".equals(authHistory.getAuthenticatorName())) {
//                        try {
//                            UserSessionStore.getInstance().removeFederatedAuthSessionInfo(context.getSessionIdentifier());
//                            break;
//                        } catch (UserSessionException e) {
//                            throw new FrameworkException("Error while deleting federated authentication session details for"
//                                    + " the session context key :" + context.getSessionIdentifier(), e);
//                        }
//                    }
//                }
//            }
//
//            AuthenticationContextCache authCache = AuthenticationContextCache.getInstance();
//            sessionContext = FrameworkUtils.getSessionContextFromCache(context.getCallerSessionKey());
//            
//            // Remove federated authentication session details from the database.
//            if (sessionContext != null && StringUtils.isNotBlank(context.getSessionIdentifier()) &&
//                    sessionContext.getSessionAuthHistory().getHistory() != null) {
//                for (AuthHistory authHistory : sessionContext.getSessionAuthHistory().getHistory()) {
//                	log.error("iiiiiiiiiiiiiiiiiiiii: " + authHistory.getAuthenticatorName());
//                    if ("AACAuthenticator".equals(authHistory.getAuthenticatorName())) {
//                        try {
//                            UserSessionStore.getInstance().removeFederatedAuthSessionInfo(context.getSessionIdentifier());
//                            break;
//                        } catch (UserSessionException e) {
//                            throw new FrameworkException("Error while deleting federated authentication session details for"
//                                    + " the session context key :" + context.getSessionIdentifier(), e);
//                        }
//                    }
//                }
//            }
//            FrameworkUtils.removeSessionContextFromCache(context.getCallerSessionKey());
//            FrameworkUtils.removeAuthenticationContextFromCache(context.getCallerSessionKey());
//            FrameworkUtils.removeAuthenticationRequestFromCache(context.getCallerSessionKey());
            
            
            provHandler.handle(roles, subject, claimMap, "As in username", tenantDomain);
        } catch (OAuthProblemException e) {
        	throw new AuthenticationFailedException("Authentication process failed ", e);
		} catch (FrameworkException e) {
			throw new AuthenticationFailedException("Error while provisioning tenant and user ", e);
		}
    }

    protected Map<ClaimMapping, String> getSubjectAttributes(Map<String, Object> userInfo) {
		Map<ClaimMapping, String> claims = new HashMap<>();
		try {
			claims.put(ClaimMapping.build("http://wso2.org/claims/username", 	"email", null, false), userInfo.get("email").toString());
			claims.put(ClaimMapping.build("http://wso2.org/claims/givenname", 	"given_name", null, false), userInfo.get("given_name").toString());
			claims.put(ClaimMapping.build("http://wso2.org/claims/fullname", 	"name", null, false), userInfo.get("name").toString());
			claims.put(ClaimMapping.build("http://wso2.org/claims/emailaddress", 	"preferred_username", null, false), userInfo.get("preferred_username").toString());
			claims.put(ClaimMapping.build("http://wso2.org/claims/lastname", 	"family_name", null, false), userInfo.get("family_name").toString());
		} catch (Exception e) {
			log	.error("Error occurred while accessing user info endpoint", e);
		}
		return claims;
	}
    
    protected Map<String, String> getSubjectAttr(Map<String, Object> userInfo) {
		Map<String, String> claims = new HashMap<>();
		try {
			claims.put("http://wso2.org/claims/username", userInfo.get("email").toString());
			claims.put("http://wso2.org/claims/givenname", userInfo.get("given_name").toString());
			claims.put("http://wso2.org/claims/fullname", userInfo.get("name").toString());
			claims.put("http://wso2.org/claims/emailaddress", userInfo.get("preferred_username").toString());
			claims.put("http://wso2.org/claims/lastname", userInfo.get("family_name").toString());
//			claims.put("http://wso2.org/claims/role", "Internal/publisher,Internal/everyone,admin");
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
        
        Property jwkEP = new Property();
        jwkEP.setDisplayName("JWK URL");
        jwkEP.setName(AACAuthenticatorConstants.JWK_ENDPOINT);
        jwkEP.setDescription("Enter value corresponding to JWK enpoint.");
        jwkEP.setDisplayOrder(7);
        configProperties.add(jwkEP);
        
        return configProperties;
    }   
        
    private boolean isProvider(Object roleList) {
    	JSONArray jsonArray = (JSONArray)roleList; 
    	boolean isProvider = false;
    	String roleName = "ROLE_NORMAL";
    	String roleItem;
    	for(int i = 0;i<jsonArray.toArray().length; i++) {
    		roleItem = jsonArray.get(i).toString();
    		if(roleItem.contains(":")) {
    			roleName = roleItem.split(":")[1];
    			if(roleName.equals("ROLE_PROVIDER")) {
    	    		isProvider = true;
    	    		break;
    	    	}
    		}
    	}
    	log.info("isProvider? " + isProvider);
    	return isProvider;
    }
    
    private JWTClaimsSet verifyToken(String token, String jwk) {
    	SignedJWT signedJWT;
    	JWTClaimsSet claimsSet = null;
    	try {
			signedJWT = SignedJWT.parse(token);
	    	JWKSBasedJWTValidator jwksBasedJWTValidator = new JWKSBasedJWTValidator();
			boolean verified = jwksBasedJWTValidator.validateSignature(signedJWT.getParsedString(), jwk, signedJWT.getHeader().getAlgorithm().getName(), null);
			log.info("verified? " + verified);
			if(verified)
				return parseJWT(signedJWT);
					
		} catch (IdentityOAuth2Exception e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
    	return claimsSet;
    }
    
    private JWTClaimsSet parseJWT(SignedJWT signedJWT) {
    	JWTClaimsSet claimsSet = null;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            log.error("Error when trying to retrieve claimsSet from the JWT", e);
        }
        return claimsSet;
    }
}

