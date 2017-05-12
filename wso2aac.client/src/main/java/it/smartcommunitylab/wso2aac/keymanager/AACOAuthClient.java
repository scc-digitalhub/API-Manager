/*
 *
 *   Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package it.smartcommunitylab.wso2aac.keymanager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.client.SubscriberKeyMgtClientPool;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import it.smartcommunitylab.wso2aac.keymanager.model.AACResource;
import it.smartcommunitylab.wso2aac.keymanager.model.AACService;
import it.smartcommunitylab.wso2aac.keymanager.model.AACTokenValidation;
import it.smartcommunitylab.wso2aac.keymanager.model.ClientAppBasic;

public class AACOAuthClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(AACOAuthClient.class);
    
    private KeyManagerConfiguration configuration;

    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {
        this.configuration = configuration;
        SubscriberKeyMgtClientPool.getInstance().setConfiguration(this.configuration);
    }

    /**
     * This method will Register the client in Authorization Server.
     *
     * @param oauthAppRequest this object holds all parameters required to register an OAuth Client.
     */
    @Override
	public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

		BufferedReader reader = null;
		HttpClient httpClient = getHttpClient();
		ApiMgtDAO dao = ApiMgtDAO.getInstance();

		ObjectMapper mapper = new ObjectMapper();
		mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker()
                .withFieldVisibility(JsonAutoDetect.Visibility.ANY)
                .withGetterVisibility(JsonAutoDetect.Visibility.ANY)
                .withSetterVisibility(JsonAutoDetect.Visibility.ANY)
                .withCreatorVisibility(JsonAutoDetect.Visibility.ANY));

		try {
			OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();
			
			log.debug("Creating a new oAuthApp in Authorization Server");

			KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

			String registrationEndpoint = config.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
			String registrationToken = getOauthToken();

			ClientAppBasic app = convertRequest(oAuthApplicationInfo);
			
			HttpPost httpPost = new HttpPost(registrationEndpoint.trim() + "/wso2/client/" + app.getUserName());

			String jsonPayload = mapper.writeValueAsString(app);

			httpPost.setEntity(new StringEntity(jsonPayload, ClientConstants.UTF_8));
			httpPost.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);
			httpPost.setHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + registrationToken);

			HttpResponse response = httpClient.execute(httpPost);
			int responseCode = response.getStatusLine().getStatusCode();

			HttpEntity entity = response.getEntity();
			reader = new BufferedReader(new InputStreamReader(entity.getContent(), ClientConstants.UTF_8));

			if (HttpStatus.SC_OK == responseCode) {

				app = mapper.readValue(reader, ClientAppBasic.class);

            	Map infoMap = mapper.convertValue(oAuthApplicationInfo, Map.class);
            	Map pars = (Map)infoMap.get("parameters");
				
                String tokenScope = (String) oAuthApplicationInfo.getParameter("tokenScope");
		        String tokenScopes[] = new String[1];
		        tokenScopes[0] = tokenScope;                
            	
				OAuthApplicationInfo respOAuthApplicationInfo = convertResponse(app);
				respOAuthApplicationInfo.addParameter("tokenScope", "" + Lists.newArrayList(tokenScope));
				
				respOAuthApplicationInfo.setClientId(app.getClientId());
				respOAuthApplicationInfo.setClientSecret(app.getClientSecret());
				
				oauthAppRequest.setOAuthApplicationInfo(respOAuthApplicationInfo);
				
				storeApplication(respOAuthApplicationInfo);
				
				return respOAuthApplicationInfo;
			} else {
				handleException("Some thing wrong here while registering the new client " + "HTTP Error response code is " + responseCode);
			}

		} catch (Exception e) {
			cleanupRegistrationByAppName(oauthAppRequest.getOAuthApplicationInfo().getClientName(), (String)oauthAppRequest.getOAuthApplicationInfo().getParameter("username"), (String)oauthAppRequest.getOAuthApplicationInfo().getParameter("key_type"));
			handleException("Error registering client app.", e);
		} finally {
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			httpClient.getConnectionManager().shutdown();
		}
		return null;
	}
    
    private void storeApplication(OAuthApplicationInfo oauthApplicationInfo) throws Exception {
    	OAuthAppDO app = new OAuthAppDO();
    	
    	app.setApplicationName(oauthApplicationInfo.getClientName());
    	app.setCallbackUrl(oauthApplicationInfo.getCallBackURL());
    	app.setGrantTypes((String)oauthApplicationInfo.getParameter("grant_types"));
    	app.setOauthConsumerKey(oauthApplicationInfo.getClientId());
    	app.setOauthConsumerSecret(oauthApplicationInfo.getClientSecret());
    	app.setPkceMandatory(false);
    	app.setPkceSupportPlain(false);
    	app.setOauthVersion("OAuth-2.0");
    	
    	AuthenticatedUser user = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier((String)oauthApplicationInfo.getParameter("username"));
    	app.setUser(user);
    	
    	OAuthAppDAO dao = new OAuthAppDAO();
    	
    	dao.addOAuthApplication(app);
    }    
    

    private org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo convertAppInfo(OAuthApplicationInfo oAuthApplicationInfo) {
        org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo applicationToCreate = new org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo();
        applicationToCreate.setIsSaasApplication(oAuthApplicationInfo.getIsSaasApplication());
        applicationToCreate.setCallBackURL(oAuthApplicationInfo.getCallBackURL());
        applicationToCreate.setClientName(oAuthApplicationInfo.getClientName());
        applicationToCreate.setAppOwner((String)oAuthApplicationInfo.getParameter("username"));
        applicationToCreate.setJsonString(oAuthApplicationInfo.getJsonString());
    	
    	return applicationToCreate;
    }
    
    private OAuthApplicationInfo convertAppInfo(org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo oAuthApplicationInfo) throws Exception {
    	OAuthApplicationInfo info = new OAuthApplicationInfo();
    	info.setIsSaasApplication(oAuthApplicationInfo.getIsSaasApplication());
    	info.setCallBackURL(oAuthApplicationInfo.getCallBackURL());
    	info.setClientName(oAuthApplicationInfo.getClientName());
    	info.setAppOwner(oAuthApplicationInfo.getAppOwner());
    	info.setJsonString(oAuthApplicationInfo.getJsonString());
    	
    	ObjectMapper mapper = new  ObjectMapper();
    	Map pars = mapper.readValue(info.getJsonString(), Map.class);
    	info.putAll(pars);
    	
    	return info;
    }    
    
    
    private ClientAppBasic convertRequest(OAuthApplicationInfo oAuthApplicationInfo) throws Exception {
        ObjectMapper mapper = new  ObjectMapper();
        
        Map parametersMap = mapper.readValue(oAuthApplicationInfo.getJsonString(), Map.class);
        
        String userName = (String)parametersMap.get("username");
        String keyType = (String)parametersMap.get("key_type");
        String clientName = oAuthApplicationInfo.getClientName();
        
        ClientAppBasic client = new ClientAppBasic();
        
        client.setClientId(oAuthApplicationInfo.getClientId());
        client.setName(userName + "_" + clientName + "_" + keyType);

        String grants = (String)parametersMap.get("grant_types");
        Set<String> grantsSet = Sets.newHashSet(grants.split(","));
        client.setGrantedTypes(grantsSet);
        
        client.setRedirectUris(oAuthApplicationInfo.getCallBackURL());
        client.setUserName(userName);
        client.setScope(((String)parametersMap.get("tokenScope")).replace(" ", ","));
        
        client.setParameters(oAuthApplicationInfo.getJsonString());
        
        return client;
    }
    
    private OAuthApplicationInfo convertResponse(ClientAppBasic app) throws Exception {
    	ObjectMapper mapper = new  ObjectMapper();
    	
        OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo();
        
        oAuthApplicationInfo.setClientName(app.getName());
        oAuthApplicationInfo.setCallBackURL(app.getRedirectUris());
        oAuthApplicationInfo.setClientId(app.getClientId());
        oAuthApplicationInfo.setClientSecret(app.getClientSecret());
        
        oAuthApplicationInfo.setClientName(app.getName());
        
        Map pars = mapper.readValue(app.getParameters(), Map.class);
        
        if (pars.containsKey("grant_types")) {
        	pars.put("grant_types", ((String)pars.get("grant_types")).replace(",", " "));
        }
        
        pars.put("redirect_uris", app.getRedirectUris());
        pars.put("client_name", app.getName());
        
        oAuthApplicationInfo.putAll(pars);
        
        return oAuthApplicationInfo;
    }    

    /**
     * This method will update an existing OAuth Client.
     *
     * @param oauthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

    	BufferedReader reader = null;
		HttpClient httpClient = getHttpClient();
		ObjectMapper mapper = new ObjectMapper();

		try {

			OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();

			log.debug("Updating an oAuthApp in Authorization Server");

			KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

			String registrationEndpoint = config.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
			String registrationToken = getOauthToken();

			ClientAppBasic app = convertRequest(oAuthApplicationInfo);
			
			HttpPut httpPost = new HttpPut(registrationEndpoint.trim() + "/wso2/client/" + app.getClientId());

			String jsonPayload = mapper.writeValueAsString(app);

			httpPost.setEntity(new StringEntity(jsonPayload, ClientConstants.UTF_8));
			httpPost.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);
			httpPost.setHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + registrationToken);

			HttpResponse response = httpClient.execute(httpPost);
			int responseCode = response.getStatusLine().getStatusCode();

			HttpEntity entity = response.getEntity();
			reader = new BufferedReader(new InputStreamReader(entity.getContent(), ClientConstants.UTF_8));

			if (HttpStatus.SC_OK == responseCode) {

				app = mapper.readValue(reader, ClientAppBasic.class);

				oAuthApplicationInfo = convertResponse(app);

				return oAuthApplicationInfo;
			} else {
				handleException("Some thing wrong here while updating the client " + "HTTP Error response code is " + responseCode);
			}

		} catch (Exception e) {
			cleanupRegistrationByAppName(oauthAppRequest.getOAuthApplicationInfo().getClientName(), (String)oauthAppRequest.getOAuthApplicationInfo().getParameter("username"), (String)oauthAppRequest.getOAuthApplicationInfo().getParameter("key_type"));
			handleException("Error updating client app.", e);
		} finally {
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			httpClient.getConnectionManager().shutdown();
		}
		return null;
	}

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public void deleteApplication(String clientId) throws APIManagementException {
    	OAuthAppDAO dao = new OAuthAppDAO();
    	
        HttpClient client = getHttpClient();
   	
        BufferedReader reader = null;
    	
        log.info("Deleting a new OAuth Client in Authorization Server..");

        String registrationUrl = configuration.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
        String accessToken = getOauthToken();

        try {
            HttpDelete request = new HttpDelete(registrationUrl.trim() + "/wso2/client/" + clientId);
            //set authorization header.
            request.addHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + accessToken);
            HttpResponse response = client.execute(request);

            int responseCode = response.getStatusLine().getStatusCode();

            HttpEntity entity = response.getEntity();

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));

            if (responseCode != HttpStatus.SC_NOT_FOUND && responseCode != HttpStatus.SC_OK) {
            	handleException("Something went wrong while deleting client " + clientId);
            }
            
            dao.removeConsumerApplication(clientId);
            
//            SubscriberKeyMgtClient keyMgtClient = null;
//            keyMgtClient = SubscriberKeyMgtClientPool.getInstance().get();
//            keyMgtClient.deleteOAuthApplication(clientId);
//            cleanupRegistrationByClientId(clientId);
            
        } catch (Exception e) {
			handleException("Error deleting client app.", e);
		} finally {
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			client.getConnectionManager().shutdown();
		}
    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        HttpClient client = getHttpClient();
        ObjectMapper mapper = new ObjectMapper();

        String registrationURL = configuration.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
        String accessToken = getOauthToken();
        BufferedReader reader = null;

        try {
            HttpGet request = new HttpGet(registrationURL.trim() + "/wso2/client/" + consumerKey);
            //set authorization header.
            request.addHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + accessToken);
            HttpResponse response = client.execute(request);

            int responseCode = response.getStatusLine().getStatusCode();

            HttpEntity entity = response.getEntity();

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));

            if (responseCode == HttpStatus.SC_OK) {

            	ClientAppBasic app = mapper.readValue(reader, ClientAppBasic.class);
            	
            	OAuthApplicationInfo oAuthApplicationInfo = convertResponse(app);
            	
            	oAuthApplicationInfo.addParameter("client_name", app.getName());
            	
				return oAuthApplicationInfo;
            } else {
                handleException("Something went wrong while retrieving clients for consumer key " + consumerKey);
            }

        } catch (Exception e) {
			handleException("Error retrieving client app.", e);
		} finally {
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			client.getConnectionManager().shutdown();
		}
		return null;
    }

	@Override
	public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(OAuthApplicationInfo oAuthApplication, AccessTokenRequest tokenRequest) throws APIManagementException {
		ObjectMapper mapper = new ObjectMapper(); 
		mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker()
                .withFieldVisibility(JsonAutoDetect.Visibility.ANY)
                .withGetterVisibility(JsonAutoDetect.Visibility.ANY)
                .withSetterVisibility(JsonAutoDetect.Visibility.ANY)
                .withCreatorVisibility(JsonAutoDetect.Visibility.ANY));		
		
		AccessTokenRequest req = new AccessTokenRequest();
		req.setClientId(oAuthApplication.getClientId());
		req.setClientSecret(oAuthApplication.getClientSecret());
		req.setCallbackURI(oAuthApplication.getCallBackURL());
		req.setScope(tokenRequest.getScope());
		req.setGrantType("client_credentials");
		req.setValidityPeriod(Long.parseLong((String)oAuthApplication.getParameter("validityPeriod")));
		
		return req;
	}

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {

    	BufferedReader reader = null;
		HttpClient httpClient = getHttpClient();
		ObjectMapper mapper = new ObjectMapper();    	
		mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker()
                .withFieldVisibility(JsonAutoDetect.Visibility.ANY)
                .withGetterVisibility(JsonAutoDetect.Visibility.ANY)
                .withSetterVisibility(JsonAutoDetect.Visibility.ANY)
                .withCreatorVisibility(JsonAutoDetect.Visibility.ANY));			
    	
		try {
			revokeTokenLocally(tokenRequest);

			log.debug("Creating a new oAuthApp in Authorization Server");

			KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
			
			String registrationEndpoint = config.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
			String registrationToken = getOauthToken();

			
			if (tokenRequest.getTokenToRevoke() != null && !"".equals(tokenRequest.getTokenToRevoke())) {
				HttpPost httpPost = new HttpPost(registrationEndpoint.trim() + "/wso2/client/token_revoke/" + tokenRequest.getTokenToRevoke());

				httpPost.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);
				httpPost.setHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + registrationToken);

				HttpResponse response = httpClient.execute(httpPost);
				int responseCode = response.getStatusLine().getStatusCode();

				HttpEntity entity = response.getEntity();
				reader = new BufferedReader(new InputStreamReader(entity.getContent(), ClientConstants.UTF_8));

				if (HttpStatus.SC_OK != responseCode) {
					handleException("Some thing wrong here while revoking the token " + "HTTP Error response code is " + responseCode);
				}
				
				EntityUtils.consume(entity);
			}			
			
			if (tokenRequest.getScope() != null) {
				{
					String url = registrationEndpoint.trim() + "/wso2/client/scope/" + tokenRequest.getClientId() + "?scope="
							+ Joiner.on(",").join(tokenRequest.getScope()).replace(" ", ",");					
					
					HttpPost httpPost = new HttpPost(url);

					httpPost.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);
					httpPost.setHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + registrationToken);

					HttpResponse response = httpClient.execute(httpPost);
					int responseCode = response.getStatusLine().getStatusCode();

					HttpEntity entity = response.getEntity();
					reader = new BufferedReader(new InputStreamReader(entity.getContent(), ClientConstants.UTF_8));

					if (HttpStatus.SC_OK != responseCode) {
						handleException("Some thing wrong here while updating scope " + "HTTP Error response code is " + responseCode);
					}

					EntityUtils.consume(entity);
				}
			}
			
			{
				// validity_period doesn't work in oauth
				
				String url = registrationEndpoint.trim() + "/oauth/token?" + "client_id=" + tokenRequest.getClientId() + "&client_secret=" + tokenRequest.getClientSecret()
						+ "&grant_type=" + (tokenRequest.getGrantType() != null ? tokenRequest.getGrantType() : "client_credentials") + "&validity_period=" + tokenRequest.getValidityPeriod()
						+ (tokenRequest.getScope() != null ? ("&scope=" + Joiner.on(" ").join(tokenRequest.getScope())).replace(" ", "%20") : "");
				
				HttpPost httpPost = new HttpPost(url);

				httpPost.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);
				httpPost.setHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + registrationToken);

				HttpResponse response = httpClient.execute(httpPost);
				int responseCode = response.getStatusLine().getStatusCode();

				HttpEntity entity = response.getEntity();
				reader = new BufferedReader(new InputStreamReader(entity.getContent(), ClientConstants.UTF_8));

				if (HttpStatus.SC_OK == responseCode) {

					Map token = mapper.readValue(reader, Map.class);

					AccessTokenInfo tokenInfo = new AccessTokenInfo();
					tokenInfo.setAccessToken((String) token.get("access_token"));
					tokenInfo.setValidityPeriod((long) (Integer) token.get("expires_in"));
					tokenInfo.setIssuedTime(System.currentTimeMillis());

					String[] scopes = new String[1];
					scopes[0] = (String) token.get("scope");

					tokenInfo.setScope(scopes);

					tokenInfo.setConsumerKey(tokenRequest.getClientId());
					tokenInfo.setConsumerSecret(tokenRequest.getClientSecret());

					storeTokenLocally(tokenInfo);

					return tokenInfo;
				} else {
					handleException("Some thing wrong here while retrieving the token " + "HTTP Error response code is " + responseCode);
				}
			}

		} catch (Exception e) {
			cleanupRegistrationByClientId(tokenRequest.getClientId());
			handleException("Error getting the token.", e);
		} finally {
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			httpClient.getConnectionManager().shutdown();
		}
		return null;
	}

	private void revokeTokenLocally(AccessTokenRequest tokenRequest) throws Exception {
		String revokeEndpoint = configuration.getParameter(APIConstants.REVOKE_URL);

		// Call the /revoke only if there's a token to be revoked.
		if (tokenRequest.getTokenToRevoke() != null && !"".equals(tokenRequest.getTokenToRevoke())) {
			URL revokeEndpointURL = new URL(revokeEndpoint);
			String revokeEndpointProtocol = revokeEndpointURL.getProtocol();
			int revokeEndpointPort = revokeEndpointURL.getPort();

			HttpClient revokeEPClient = APIUtil.getHttpClient(revokeEndpointPort, revokeEndpointProtocol);

			HttpPost httpRevokePost = new HttpPost(revokeEndpoint);

			// Request parameters.
			List<NameValuePair> revokeParams = new ArrayList<NameValuePair>(3);
			revokeParams.add(new BasicNameValuePair(OAuth.OAUTH_CLIENT_ID, tokenRequest.getClientId()));
			revokeParams.add(new BasicNameValuePair(OAuth.OAUTH_CLIENT_SECRET, tokenRequest.getClientSecret()));
			revokeParams.add(new BasicNameValuePair("token", tokenRequest.getTokenToRevoke()));

			// Revoke the Old Access Token
			httpRevokePost.setEntity(new UrlEncodedFormEntity(revokeParams, "UTF-8"));
			int statusCode;
			try {
				HttpResponse revokeResponse = revokeEPClient.execute(httpRevokePost);
				statusCode = revokeResponse.getStatusLine().getStatusCode();
			} finally {
			}

			if (statusCode != 200) {
				throw new RuntimeException("Token revoke failed : HTTP error code : " + statusCode);
			} else {
				if (log.isDebugEnabled()) {
					log.debug("Successfully submitted revoke request for old application token. HTTP status : 200");
				}
			}
		}
	}
    
    private void storeTokenLocally(AccessTokenInfo tokenInfo) throws Exception {
    	Connection connection = IdentityDatabaseUtil.getDBConnection();
    	
    	try {
    	AccessTokenDO token = new AccessTokenDO();
    	
        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(tokenInfo.getConsumerKey());
        
        String tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        token.setTenantID(OAuth2Util.getTenantId(tenantDomain));    	
    	
    	token.setAccessToken(tokenInfo.getAccessToken());
    	token.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
    	token.setConsumerKey(tokenInfo.getConsumerKey());
    	token.setGrantType("client_credentials");
    	token.setScope(tokenInfo.getScopes());
    	token.setValidityPeriod(tokenInfo.getValidityPeriod());
    	token.setIssuedTime(new Timestamp(tokenInfo.getIssuedTime()));
    	token.setValidityPeriod(tokenInfo.getValidityPeriod());
    	token.setValidityPeriodInMillis(tokenInfo.getValidityPeriod() * 1000L);
    	token.setRefreshTokenIssuedTime(new Timestamp(tokenInfo.getIssuedTime()));
    	token.setTokenId(UUID.randomUUID().toString());
    	token.setTokenType("APPLICATION");

    	OAuthIssuer oAuthIssuerImpl = OAuthServerConfiguration.getInstance().getOAuthTokenGenerator();
    	token.setRefreshToken(oAuthIssuerImpl.refreshToken());
        
    	AuthenticatedUser user = oAuthAppDO.getUser();
    	token.setAuthzUser(user);
    	
    	TokenMgtDAO tokenDAO = new TokenMgtDAO();
    	
    	tokenDAO.storeAccessToken(tokenInfo.getAccessToken(), tokenInfo.getConsumerKey(), token, connection, user.getUserStoreDomain());
    	connection.commit();
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }
    
    @Override
    public AccessTokenInfo getTokenMetaData(String token) throws APIManagementException {
    	AccessTokenInfo tokenInfo = new AccessTokenInfo();
    	tokenInfo.setAccessToken(token);
    	
    	HttpClient client = getHttpClient();
        ObjectMapper mapper = new ObjectMapper();

        String registrationURL = configuration.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
//        String accessToken = getOauthToken();
        BufferedReader reader = null;

        try {
            HttpGet request = new HttpGet(registrationURL.trim() + "/resources/token");
            //set authorization header.
            request.addHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + token);
            HttpResponse response = client.execute(request);

            int responseCode = response.getStatusLine().getStatusCode();

            HttpEntity entity = response.getEntity();

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));

            if (responseCode == HttpStatus.SC_OK) {

            	AACTokenValidation validation = mapper.readValue(reader, AACTokenValidation.class);
            	
            	tokenInfo.setApplicationToken(validation.isApplicationToken());
            	tokenInfo.setConsumerKey(validation.getClientId());
            	tokenInfo.setScope(validation.getScope());
            	tokenInfo.setTokenValid(validation.isValid());
            	tokenInfo.setIssuedTime(validation.getIssuedTime());
            	tokenInfo.setValidityPeriod(validation.getValidityPeriod());
            	tokenInfo.setEndUserName(validation.getUsername());
            } else {
                handleException("Something went wrong while checking authorization for token " + token);
            }

        } catch (Exception e) {
			handleException("Error checking authorization for token.", e);
		} finally {
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			client.getConnectionManager().shutdown();
		}    	
    	
    	
    	return tokenInfo;
    }
    

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String jsonInput) throws APIManagementException {
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param appInfoRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest appInfoRequest)
            throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = appInfoRequest.getOAuthApplicationInfo();
        return oAuthApplicationInfo;
    }

	@Override
	public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
		BufferedReader reader = null;
		HttpClient httpClient = getHttpClient();

		ObjectMapper mapper = new ObjectMapper();

		try {
			AACService service = new AACService();

			service.setDescription(api.getDescription());
			
			String name = extractDomainFromTenant(api.getId().getProviderName()) + "-" + api.getId().getApiName() + "-" + api.getId().getVersion(); 
			service.setServiceName(name);

			for (Scope scope : api.getScopes()) {
				AACResource resource = new AACResource();
				resource.setDescription(scope.getDescription());
				resource.setName(scope.getName());
				resource.setResourceUri(scope.getKey());

				List<String> roles = Lists.newArrayList(scope.getRoles().split(","));
				resource.setRoles(roles);

				service.getResources().add(resource);
			}

			KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

			String registrationEndpoint = config.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
			String registrationToken = getOauthToken();

			HttpPost httpPost = new HttpPost(registrationEndpoint.trim() + "/wso2/resources/" + api.getId().getProviderName());

			String jsonPayload = mapper.writeValueAsString(service);

			httpPost.setEntity(new StringEntity(jsonPayload, ClientConstants.UTF_8));
			httpPost.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);
			httpPost.setHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + registrationToken);

			HttpResponse response = httpClient.execute(httpPost);
			int responseCode = response.getStatusLine().getStatusCode();

			HttpEntity entity = response.getEntity();
			reader = new BufferedReader(new InputStreamReader(entity.getContent(), ClientConstants.UTF_8));

			if (HttpStatus.SC_OK == responseCode) {

				return true;
			} else {
				handleException("Some thing wrong here while registering the new API " + "HTTP Error response code is " + responseCode);
			}

		} catch (Exception e) {
			handleException("Error registering API.", e);
		}

		// TODO false if fail?
		return true;
	}
	
	private String extractDomainFromTenant(String tenant) {
		String un = tenant.replace("-AT-", "@");

		int index = un.indexOf('@');
		int lastIndex = un.lastIndexOf('@');
		
		if (index != lastIndex) {
			un = un.substring(lastIndex + 1);
		} else {
			un = "carbon.super";
		}
		return un;
	}	

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {
		HttpClient httpClient = getHttpClient();

		try {
			KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

			String registrationEndpoint = config.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
			String registrationToken = getOauthToken();

			HttpDelete httpDelete = new HttpDelete(registrationEndpoint.trim() + "/wso2/resources/" + apiID);

			httpDelete.setHeader(ClientConstants.AUTHORIZATION, ClientConstants.BEARER + registrationToken);

			HttpResponse response = httpClient.execute(httpDelete);
			int responseCode = response.getStatusLine().getStatusCode();

			if (HttpStatus.SC_OK != responseCode) {
				handleException("Some thing wrong here while deleting the new API " + "HTTP Error response code is " + responseCode);
			}

		} catch (Exception e) {
			handleException("Error deleting API.", e);
		}

	}

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }
    
	private String getOauthToken() throws APIManagementException {
		HttpClient httpClient = getHttpClient();
		BufferedReader reader = null;
		KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
		ObjectMapper mapper = new ObjectMapper();
		mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker().withFieldVisibility(JsonAutoDetect.Visibility.ANY).withGetterVisibility(JsonAutoDetect.Visibility.ANY)
				.withSetterVisibility(JsonAutoDetect.Visibility.ANY).withCreatorVisibility(JsonAutoDetect.Visibility.ANY));

		try {
			String registrationEndpoint = config.getParameter(ClientConstants.CLIENT_REG_ENDPOINT);
			String clientId = config.getParameter(ClientConstants.INTROSPECTION_CK);
			String clientSecret = config.getParameter(ClientConstants.INTROSPECTION_CS);

			// validity_period doesn't work in oauth
			HttpPost httpPost = new HttpPost(registrationEndpoint.trim() + "/oauth/token?" + "client_id=" + clientId + "&client_secret=" + clientSecret + "&grant_type=client_credentials");

			httpPost.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);

			HttpResponse response = httpClient.execute(httpPost);
			int responseCode = response.getStatusLine().getStatusCode();

			HttpEntity entity = response.getEntity();
			reader = new BufferedReader(new InputStreamReader(entity.getContent(), ClientConstants.UTF_8));

			if (HttpStatus.SC_OK == responseCode) {

				Map tokenMap = mapper.readValue(reader, Map.class);

				String token = (String) tokenMap.get("access_token");

				return token;
			} else {
				handleException("Some thing wrong here while retrieving the token " + "HTTP Error response code is " + responseCode);
			}
		} catch (Exception e) {
			handleException("Error registering client app.", e);
		} finally {
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			httpClient.getConnectionManager().shutdown();
		}
		return null;
	}
	
    public static final String DELETE_MAPPING = "DELETE FROM AM_APPLICATION_KEY_MAPPING WHERE APPLICATION_ID=? AND KEY_TYPE=?";
    public static final String DELETE_REGISTRATION = "DELETE FROM AM_APPLICATION_REGISTRATION WHERE APP_ID=? AND TOKEN_TYPE=?";
    public static final String DELETE_OAUTH = "DELETE FROM IDN_OAUTH_CONSUMER_APPS WHERE APP_NAME=?";
    
    private void cleanupRegistrationByClientId(String clientId) throws APIManagementException {
    	ApiMgtDAO dao = ApiMgtDAO.getInstance();
    	Map map = dao.getApplicationIdAndTokenTypeByConsumerKey(clientId);
    	cleanupRegistration(Integer.parseInt((String)map.get("application_id")), (String)map.get("token_type"));
    }    
    
    private void cleanupRegistrationByAppName(String appName, String userName, String tokenType) throws APIManagementException {
    	ApiMgtDAO dao = ApiMgtDAO.getInstance();
    	int id = dao.getApplicationId(appName, userName);
    	cleanupRegistration(id, tokenType);
    	cleanupOauthApp(appName);
    }    
    
	private void cleanupRegistration(int id, String tokenType) throws APIManagementException {
		Connection conn = null;
		PreparedStatement ps1 = null;
		PreparedStatement ps2 = null;

		try {
			conn = APIMgtDBUtil.getConnection();
			conn.setAutoCommit(false);			
			
			ps1 = conn.prepareStatement(DELETE_MAPPING);
			ps1.setInt(1, id);
			ps1.setString(2, tokenType);
			ps1.execute();
			
			ps2 = conn.prepareStatement(DELETE_REGISTRATION);
			ps2.setInt(1, id);
			ps2.setString(2, tokenType);
			ps2.execute();			

			conn.commit();
		} catch (SQLException e) {
			try {
				if (conn != null) {
					conn.rollback();
				}
			} catch (SQLException e1) {
				handleException("Error occurred while Rolling back changes done on Application Registration", e1);
			}
			handleException("Error occurred while cleaning up : " + id, e);
		} finally {
			APIMgtDBUtil.closeStatement(ps1);
			APIMgtDBUtil.closeStatement(ps2);
			APIMgtDBUtil.closeAllConnections(ps1, conn, null);
		}
	}
	
	private void cleanupOauthApp(String appName) throws APIManagementException {
		Connection conn = null;
		PreparedStatement ps1 = null;

		try {
			conn = APIMgtDBUtil.getConnection();
			conn.setAutoCommit(false);			
			
			ps1 = conn.prepareStatement(DELETE_OAUTH);
			ps1.setString(1, appName);
			ps1.execute();
			
			conn.commit();
		} catch (SQLException e) {
			try {
				if (conn != null) {
					conn.rollback();
				}
			} catch (SQLException e1) {
				handleException("Error occurred while Rolling back changes done on Application Registration", e1);
			}
			handleException("Error occurred while cleaning up : " + appName, e);
		} finally {
			APIMgtDBUtil.closeStatement(ps1);
			APIMgtDBUtil.closeAllConnections(ps1, conn, null);
		}
	}	
    

    /**
     * common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws APIManagementException
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    /**
     * common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws APIManagementException
     */
    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * This method will return HttpClient object.
     *
     * @return HttpClient object.
     */
    private HttpClient getHttpClient() {
        HttpClient httpClient = new DefaultHttpClient();
        return httpClient;
    }
    
}
