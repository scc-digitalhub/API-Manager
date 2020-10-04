package it.smartcommunitylab.wso2aac.keymanager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.axiom.om.util.Base64;
import org.apache.axis2.util.URL;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
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
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.smartcommunitylab.wso2aac.keymanager.model.APIMClient;

public class AACKeymanager extends AbstractKeyManager {

    private KeyManagerConfiguration configuration;

    private static final Log log = LogFactory.getLog(AACKeymanager.class);

    /**
     * Create a new OAuth application in the Authorization Server.
     *
     * @param oauthAppRequest - this object contains values of oAuth app properties.
     * @return OAuthApplicationInfo object with oAuthApplication properties.
     */
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

        OAuthApplicationInfo applicationInfo = null;

        OAuthApplicationInfo requestInfo = oauthAppRequest.getOAuthApplicationInfo();
        // we need username and client name
        String username = requestInfo.getAppOwner();
        if (username == null) {
            // fetch from parameters..
            username = (String) requestInfo.getParameter("username");
        }

        String applicationName = requestInfo.getClientName();
        String keyType = (String) requestInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);

        log.debug("create (or update) application for " + username + ": " + applicationName);

        // we programmatically assign clientName for key
        String clientName = applicationName;
        if (keyType != null) {
            clientName = applicationName + "_" + keyType;
        }

        ObjectMapper mapper = objectMapper();

        // map to app
        APIMClient app = new APIMClient();
        app.setName(clientName);
        app.setUserName(username);
        app.setDisplayName(clientName);
        app.setRedirectUris(requestInfo.getCallBackURL());

        // parameters
        log.trace("request parameters " + requestInfo.getJsonString());

        String tokenScope = (String) requestInfo.getParameter("tokenScope");
        Set<String> scopes = new HashSet<>();
        if (tokenScope != null) {
            scopes.addAll(Arrays.asList(tokenScope.split(" ")));
        }

        String grantTypes = (String) requestInfo.getParameter("grant_types");
        Set<String> grantedTypes = new HashSet<>();
        if (grantTypes != null) {
            grantedTypes.addAll(Arrays.asList(grantTypes.split(",")));
        }

        app.setGrantedTypes(grantedTypes);
        app.setScope(String.join(APIMClient.SEPARATOR, scopes));

        // post to create
        String aacToken = getAdminToken();
        log.trace("aac token " + aacToken);

        // get endpoint and configure
        String aacEndpoint = configuration.getParameter(ClientConstants.CONFIG_AAC_ENDPOINT);
        URL endpointURL = new URL(aacEndpoint);
        String endpointProtocol = endpointURL.getProtocol();
        int endpointPort = endpointURL.getPort();

        String path = "/wso2/client";

        HttpClient client = APIUtil.getHttpClient(endpointPort, endpointProtocol);
        HttpPost request = new HttpPost(aacEndpoint + path);

        // pass admin auth as bearer
        request.setHeader(ClientConstants.AUTHORIZATION,
                ClientConstants.BEARER + " " + aacToken);

        try {
            String jsonPayload = mapper.writeValueAsString(app);
            request.setEntity(new StringEntity(jsonPayload, "UTF-8"));
            request.setHeader(ClientConstants.CONTENT_TYPE, ClientConstants.APPLICATION_JSON_CONTENT_TYPE);

            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();

            if (statusCode == HttpStatus.SC_OK && entity != null) {
                // we expect a client structure
                app = mapper.readValue(EntityUtils.toString(entity), APIMClient.class);

                if (app != null) {
                    log.trace("received app from provider " + app.toString());

                    applicationInfo = convertApp(app);
                    log.debug("received app from provider");

                    // no persistence for apps

                } else {
                    log.warn("application null or invalid");
                }

            } else {
                log.debug("Token or response invalid");
            }
        } catch (JsonParseException | JsonMappingException e) {
            log.error("parsing exception ", e);
        } catch (IOException e) {
            log.error("io exception ", e);
        }

        return applicationInfo;
    }

    /**
     * Update an oAuth application
     *
     * @param appInfoDTO accept an appinfoDTO object
     * @return OAuthApplicationInfo this object will contain all the properties of
     *         updated oAuth application
     */
    public OAuthApplicationInfo updateApplication(OAuthAppRequest appInfoDTO) throws APIManagementException {

        OAuthApplicationInfo requestInfo = appInfoDTO.getOAuthApplicationInfo();
        String consumerKey = requestInfo.getClientId();
        // we *always* need username and client name
        String username = requestInfo.getAppOwner();
        String applicationName = requestInfo.getClientName();
        log.debug(
                "update application for " + username + ": " + applicationName + " key " + String.valueOf(consumerKey));

        // we call create to update if existing or create as new
        OAuthApplicationInfo res = createApplication(appInfoDTO);
        
    	return res;

    }

    private OAuthApplicationInfo updateApplicationValidity(OAuthApplicationInfo requestInfo, long validitySeconds)
            throws APIManagementException {

        String clientId = requestInfo.getClientId();
        log.debug("update validity for " + String.valueOf(clientId) + " to " + String.valueOf(validitySeconds));

        if (clientId == null) {
            throw new APIManagementException("Invalid clientId");
        }

        OAuthApplicationInfo applicationInfo = null;
        ObjectMapper mapper = objectMapper();

        // put to update
        String aacToken = getAdminToken();
        log.trace("aac token " + aacToken);

        // get endpoint and configure
        String aacEndpoint = configuration.getParameter(ClientConstants.CONFIG_AAC_ENDPOINT);
        URL endpointURL = new URL(aacEndpoint);
        String endpointProtocol = endpointURL.getProtocol();
        int endpointPort = endpointURL.getPort();

        // may be larger then max int - convert
        int intVal = (int) validitySeconds;
        if (intVal < 0) intVal = Integer.MAX_VALUE;
        String path = "/wso2/client/" + clientId + "/validity/" + String.valueOf(intVal);

        HttpClient client = APIUtil.getHttpClient(endpointPort, endpointProtocol);
        HttpPatch request = new HttpPatch(aacEndpoint + path);

        // pass admin auth as bearer
        request.setHeader(ClientConstants.AUTHORIZATION,
                ClientConstants.BEARER + " " + aacToken);

        try {

            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();

            if (statusCode == HttpStatus.SC_OK && entity != null) {
                // we expect a client structure
                APIMClient app = mapper.readValue(EntityUtils.toString(entity), APIMClient.class);

                if (app != null) {
                    log.trace("received app from provider " + app.toString());

                    applicationInfo = convertApp(app);
                }

            }
        } catch (IOException e) {
            log.error("io exception ", e);
        }

        if (applicationInfo == null) {
            throw new APIManagementException("Error updating validity for client " + clientId);
        }

        return applicationInfo;
    }

    private OAuthApplicationInfo updateApplicationScopes(OAuthApplicationInfo requestInfo, String[] scopes)
            throws APIManagementException {

        String clientId = requestInfo.getClientId();
        log.debug("update scopes for " + String.valueOf(clientId) + " to " + Arrays.toString(scopes));

        if (clientId == null) {
            throw new APIManagementException("Invalid clientId");
        }

        OAuthApplicationInfo applicationInfo = null;
        ObjectMapper mapper = objectMapper();

        // put to update
        String aacToken = getAdminToken();
        log.trace("aac token " + aacToken);

        // get endpoint and configure
        String aacEndpoint = configuration.getParameter(ClientConstants.CONFIG_AAC_ENDPOINT);
        URL endpointURL = new URL(aacEndpoint);
        String endpointProtocol = endpointURL.getProtocol();
        int endpointPort = endpointURL.getPort();

        String path = "/wso2/client/" + clientId + "/scope";

        HttpClient client = APIUtil.getHttpClient(endpointPort, endpointProtocol);
        HttpPut request = new HttpPut(aacEndpoint + path);

        // pass admin auth as bearer
        request.setHeader(ClientConstants.AUTHORIZATION,
                ClientConstants.BEARER + " " + aacToken);

        List<NameValuePair> params = new ArrayList<NameValuePair>();
        Set<Object> scopeSet = new HashSet<>();
        for (String s : scopes) {
        	if (s != null) {
        		scopeSet.add(s.trim());
        	}
        }
        params.add(new BasicNameValuePair("scope", StringUtils.join(scopeSet, APIMClient.SEPARATOR)));

        try {
            request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();

            if (statusCode == HttpStatus.SC_OK && entity != null) {
                // we expect a client structure
                APIMClient app = mapper.readValue(EntityUtils.toString(entity), APIMClient.class);

                if (app != null) {
                    log.trace("received app from provider " + app.toString());

                    applicationInfo = convertApp(app);
                }

            }
        } catch (IOException e) {
            log.error("io exception ", e);
        }

        if (applicationInfo == null) {
            throw new APIManagementException("Error updating validity for client " + clientId);
        }

        return applicationInfo;
    }

    /**
     * Delete auth application
     *
     * @param consumerKey - will take consumer key as parameter
     */
    public void deleteApplication(String consumerKey) throws APIManagementException {

        log.debug("delete application for key " + consumerKey);

        String clientId = consumerKey;

        String aacToken = getAdminToken();
        log.trace("aac token " + aacToken);

        // TODO remove local tokens for this app
        //

        // get endpoint and configure
        String aacEndpoint = configuration.getParameter(ClientConstants.CONFIG_AAC_ENDPOINT);
        URL endpointURL = new URL(aacEndpoint);
        String endpointProtocol = endpointURL.getProtocol();
        int endpointPort = endpointURL.getPort();

        String path = "/wso2/client/" + clientId;

        HttpClient client = APIUtil.getHttpClient(endpointPort, endpointProtocol);
        HttpDelete request = new HttpDelete(aacEndpoint + path);

        // pass admin auth as bearer
        request.setHeader(ClientConstants.AUTHORIZATION,
                ClientConstants.BEARER + " " + aacToken);

        try {
            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();

            if (statusCode == HttpStatus.SC_OK) {
                log.debug("app deleted");

            } else {
                log.debug("token or response invalid");
            }
        } catch (IOException e) {
            log.error("io exception ", e);
        }

    }

    /**
     * Populate auth application.this will fetch data from oAuth server and will
     * save properties to a java object
     *
     * @param consumerKey will take consumer key as parameter
     * @return json string
     */
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        log.debug("load application for key " + consumerKey);

        String clientId = consumerKey;

        // if we return null apim locks when AAC is offline
//        OAuthApplicationInfo applicationInfo = new OAuthApplicationInfo();
//        applicationInfo.setClientId(clientId);
        OAuthApplicationInfo applicationInfo = null;

        String aacToken = getAdminToken();
        log.trace("aac token " + aacToken);

        // get endpoint and configure
        String aacEndpoint = configuration.getParameter(ClientConstants.CONFIG_AAC_ENDPOINT);
        URL endpointURL = new URL(aacEndpoint);
        String endpointProtocol = endpointURL.getProtocol();
        int endpointPort = endpointURL.getPort();

        String path = "/wso2/client/" + clientId;

        HttpClient client = APIUtil.getHttpClient(endpointPort, endpointProtocol);
        HttpGet request = new HttpGet(aacEndpoint + path);

        // pass admin auth as bearer
        request.setHeader(ClientConstants.AUTHORIZATION,
                ClientConstants.BEARER + " " + aacToken);

        try {
            ObjectMapper mapper = objectMapper();
            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();

            if (statusCode == HttpStatus.SC_OK && entity != null) {
                // we expect a client structure
                APIMClient app = mapper.readValue(EntityUtils.toString(entity), APIMClient.class);

                if (app != null) {
                    log.trace("received app from provider " + app.toString());

                    applicationInfo = convertApp(app);
                    log.debug("received app from provider");

                } else {
                    log.warn("application null or invalid");
                }

            } else {
                log.debug("token or response invalid");
            }
        } catch (JsonParseException | JsonMappingException e) {
            log.error("parsing exception ", e);
        } catch (IOException e) {
            log.error("io exception ", e);
        }

        return applicationInfo;
    }

    private OAuthApplicationInfo convertApp(APIMClient app) {
        OAuthApplicationInfo applicationInfo = new OAuthApplicationInfo();
        applicationInfo.setClientId(app.getClientId());
        applicationInfo.setClientName(app.getName());
        applicationInfo.setClientSecret(app.getClientSecret());
        applicationInfo.setAppOwner(app.getUserName());

        String callbackURL = "";
        String[] redirects = app.getRedirectUris() != null
                ? app.getRedirectUris().split(APIMClient.SEPARATOR)
                : new String[0];
        if (redirects.length > 0) {
            callbackURL = redirects[0];
        }

        applicationInfo.setCallBackURL(callbackURL);

        // pass parameters
        Map<String, String> parameters = app.getParameters();
        if (parameters != null) {
            for (String key : parameters.keySet()) {
                applicationInfo.addParameter(key, parameters.get(key));
            }
        }

        // we also overwrite critical params
        applicationInfo.addParameter("username", app.getUserName());
        applicationInfo.addParameter("grant_types", String.join(" ", app.getGrantedTypes()));
        applicationInfo.addParameter("tokenScope", app.getScope());
        applicationInfo.addParameter("validityPeriod", app.getParameter("validityPeriod"));

        return applicationInfo;
    }

    /**
     * Store calls this method to get a new Application Access Token. This will be
     * called when getting the token for the first time and when Store needs to
     * refresh the existing token.
     * 
     * @param tokenRequest AccessTokenRequest which encapsulates parameters sent
     *                     from UI.
     * @return Details of the Generated Token. AccessToken and Validity period are a
     *         must.
     * @throws APIManagementException
     */
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {

        AccessTokenInfo token = null;

        if (tokenRequest == null) {
            log.warn("No information available to generate Token.");
            return null;
        }

        String clientId = tokenRequest.getClientId();
        String clientSecret = tokenRequest.getClientSecret();
        String userName = tokenRequest.getResourceOwnerUsername();
        String password = tokenRequest.getResourceOwnerPassword();

        if (clientId == null || clientSecret == null) {
            log.error("Invalid credentials for token request");
            return null;
        }

        // we support only client credentials or resource owner
        String gt = tokenRequest.getGrantType();
        // fix grant type name... and fallback to default since sometimes we won't get a
        // type..
        String grantType = gt != null ? gt.replace(" ", "_").toLowerCase()
                : ClientConstants.OAUTH_GRANT_CLIENT_CREDENTIALS;

        log.debug("request token " + String.valueOf(grantType) + " for client " + clientId);

        // check if we have a previous token to revoke
        // TODO

        // check request again app config, will update if needed
        OAuthApplicationInfo applicationInfo = retrieveApplication(clientId);
        if (applicationInfo == null) {
            log.error("missing application");
            return null;
        }

        // CURRENTLY DISABLED: DO NOT UPDATE VALIDITY OF AN APP. 
        
        // expect this to be in millis?
//        long validityPeriod = tokenRequest.getValidityPeriod();
//        log.debug("requested token validity " + String.valueOf(validityPeriod));
//
//        if (applicationInfo.getParameter("validityPeriod") != null) {
//            // we support setting the validity, in seconds
//            long curValidity = Long.parseLong((String) applicationInfo.getParameter("validityPeriod")) * 1000;
//
//            log.debug("token requested validity " + String.valueOf(validityPeriod) + " configured is "
//                    + String.valueOf(curValidity));
//
//            if (curValidity != validityPeriod) {
//                // update
//                applicationInfo = updateApplicationValidity(applicationInfo, validityPeriod);
//            }
//
//        }

        // input is incorrect: scope array is a singleton with space-separated scopes string: ["s1 s2"]
        String[] scopes = String.join(" ", tokenRequest.getScope()).split(" ");
        log.debug("requested token scopes " + Arrays.toString(scopes));

        // check if current config supports all these scopes
        if (applicationInfo.getParameter("tokenScope") != null) {
            String[] curScopes = ((String) applicationInfo.getParameter("tokenScope")).split(" ");

            Set<String> missingScopes = new HashSet<>();
            for (String s : scopes) {
                if (!ArrayUtils.contains(curScopes, s)) {
                    missingScopes.add(s);
                }
            }

            if (!missingScopes.isEmpty()) {
                // update config adding new scopes
                Set<String> newScopes = new HashSet<>();
                newScopes.addAll(Arrays.asList(curScopes));
                newScopes.addAll(Arrays.asList(scopes));
                applicationInfo = updateApplicationScopes(applicationInfo, newScopes.toArray(new String[0]));

            }

        }

        // get token from endpoint
        if (ClientConstants.OAUTH_GRANT_CLIENT_CREDENTIALS.equals(grantType)) {
            token = getClientCredentialsToken(clientId, clientSecret, scopes);
        } else if (ClientConstants.OAUTH_GRANT_RESOURCE_OWNER.equals(grantType)) {
            token = getResourceOwnerToken(clientId, clientSecret, scopes, userName, password);
        } else {
            // unsupported
            throw new APIManagementException("Unsupported grant type: " + String.valueOf(grantType));
        }

        if (token == null) {
            // error
            throw new APIManagementException("Token request failed for " + String.valueOf(grantType));
        }

        // TODO persist token into store via custom methods
        // optional, useful for gui to show existing tokens on reload
        token.addParameter("validityPeriod", applicationInfo.getParameter("validityPeriod"));
        
        return token;

    }

    /**
     * Get details about an access token. As a part of the response, consumer key
     * against which token was obtained must be returned.
     * 
     * @return {@code AccessTokenInfo}
     */
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {

    	log.error("GET TOCKEN META START: " + accessToken);

        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        tokenInfo.setTokenValid(false);

        String adminClientId = configuration.getParameter(ClientConstants.CONFIG_CLIENT_ID);
        String adminClientSecret = configuration.getParameter(ClientConstants.CONFIG_CLIENT_SECRET);

        if (adminClientId != null && adminClientSecret != null) {
            // get endpoint and configure
            String introspectEndpoint = configuration.getParameter(ClientConstants.CONFIG_OAUTH_INTROSPECTION_ENDPOINT);
            URL endpointURL = new URL(introspectEndpoint);
            String endpointProtocol = endpointURL.getProtocol();
            int endpointPort = endpointURL.getPort();

            HttpClient client = APIUtil.getHttpClient(endpointPort, endpointProtocol);
            HttpPost request = new HttpPost(introspectEndpoint);

            // build parameters
            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair("token", accessToken));

            // pass admin auth as basic auth header
            String secret = adminClientId + ":" + adminClientSecret;

            request.setHeader(ClientConstants.AUTHORIZATION,
                    ClientConstants.BASIC + " " + Base64.encode(secret.getBytes()));

            try {
                request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

                HttpResponse response = client.execute(request);
                int statusCode = response.getStatusLine().getStatusCode();
                HttpEntity entity = response.getEntity();

                if (statusCode == HttpStatus.SC_OK && entity != null) {
                    // we expect a json
                    JSONObject json = new JSONObject(EntityUtils.toString(entity));

                    if (json != null && json.has("active")) {
                        boolean active = json.getBoolean("active");
                        String clientId = json.getString(OAuth.OAUTH_CLIENT_ID);
                        String subject = json.getString(ClientConstants.OAUTH_SUBJECT);
                        String tokenType = json.getString(OAuth.OAUTH_TOKEN_TYPE);
                        long expires = json.getLong(ClientConstants.OAUTH_EXP);
                        long iat = json.getLong(ClientConstants.OAUTH_ISSUED_AT);
                        String[] scopes = json.getString(OAuth.OAUTH_SCOPE).split(" ");
                        String username = json.has(OAuth.OAUTH_USERNAME) ? json.getString(OAuth.OAUTH_USERNAME)
                                : subject;
                        // local check for applicationToken
                        // TODO rework
                        String grantType = json.getString("aac_grantType");
                        boolean applicationToken = ClientConstants.OAUTH_GRANT_CLIENT_CREDENTIALS.equals(grantType);

                        if (!ClientConstants.BEARER.equals(tokenType)) {
                            throw new APIManagementException(
                                    "Invalid token type received: " + String.valueOf(tokenType));
                        }

                        tokenInfo.setTokenValid(active);
                        tokenInfo.setConsumerKey(clientId);
                        tokenInfo.setScope(scopes);
//                        tokenInfo.setValidityPeriod(expires - iat);
                        // apim MAYBE expects validity as expire time in ms?
                        tokenInfo.setValidityPeriod((expires - iat) * 1000);
                        tokenInfo.setIssuedTime(iat * 1000);
                        tokenInfo.setApplicationToken(applicationToken);

                        // HARDCODED tenant, TODO implement a method for getting the tenant from token
                        // or from response
                        // need update from AAC
                        String endUsername = username + "@carbon.super";
                        tokenInfo.setEndUserName(endUsername);

                    } else {
                        log.warn("Access Token invalid or inactive");
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                    }

                } else {
                    log.debug("Token or response invalid");
                }
            } catch (IOException e) {
                log.error("Exception occurred while getting token.", e);
            } catch (JSONException e) {
                log.error("Error occurred while parsing the response.", e);
            }

        } else {
            log.warn("Admin Client Id or Secret not specified");
        }

        return tokenInfo;
    }

    /**
     * Key manager implementation should be read from hardcoded json file
     *
     * @return {@code KeyManagerConfiguration}
     */
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    /**
     * @param jsonInput this jsonInput will contain set of oAuth application
     *                  properties.
     * @return OAuthApplicationInfo object will return after parsed jsonInput
     * @throws APIManagementException
     */
    public OAuthApplicationInfo buildFromJSON(String jsonInput) throws APIManagementException {
        return null;
    }

    /**
     * @param authApplicationInfo
     * @param jsonInput           this jsonInput will contain set of oAuth
     *                            application properties.
     * @return OAuthApplicationInfo object will return after parsed jsonInput
     * @throws APIManagementException
     *
     */
    public OAuthApplicationInfo buildFromJSON(OAuthApplicationInfo authApplicationInfo, String jsonInput)
            throws APIManagementException {
        return super.buildFromJSON(authApplicationInfo, jsonInput);

    }

    /**
     * This method will parse the JSON input and add those additional values to
     * AccessTokenRequest. If its needed to pass parameters in addition to those
     * specified in AccessTokenRequest, those can be provided in the JSON input.
     * 
     * @param jsonInput    Input as a JSON. This is the same JSON passed from Store
     *                     UI.
     * @param tokenRequest Object encapsulating parameters sent from UI.
     * @return If input AccessTokenRequest is null, a new object will be returned,
     *         else the additional parameters will be added to the input object
     *         passed.
     * @throws APIManagementException
     */
    public AccessTokenRequest buildAccessTokenRequestFromJSON(String jsonInput, AccessTokenRequest tokenRequest)
            throws APIManagementException {
        return super.buildAccessTokenRequestFromJSON(jsonInput, tokenRequest);

    }

    /**
     * This method will be used if you want to create a oAuth application in
     * semi-manual mode where you must input minimum consumer key and consumer
     * secret.
     *
     * @param appInfoRequest
     * @return OAuthApplicationInfo with oAuth application properties.
     * @throws APIManagementException
     */
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest appInfoRequest) throws APIManagementException {
        // we don't really need to do anything, we will sync on create or update
        OAuthApplicationInfo oAuthApplicationInfo = appInfoRequest.getOAuthApplicationInfo();
        return oAuthApplicationInfo;
    }

    /**
     * This method will create an AccessTokenRequest using OAuthApplicationInfo
     * object. If tokenRequest is null, this will create a new object, else will
     * modify the provided AccessTokenRequest Object.
     * 
     * @param oAuthApplication
     * @param tokenRequest
     * @return AccessTokenRequest
     */
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(OAuthApplicationInfo oAuthApplication,
            AccessTokenRequest tokenRequest) throws APIManagementException {

    	if (oAuthApplication == null) {
            return tokenRequest;
        }
        if (tokenRequest == null) {
            tokenRequest = new AccessTokenRequest();
        }

        if (oAuthApplication.getClientId() == null || oAuthApplication.getClientSecret() == null) {
            throw new APIManagementException("Consumer key or Consumer Secret missing.");
        }
        tokenRequest.setClientId(oAuthApplication.getClientId());
        tokenRequest.setClientSecret(oAuthApplication.getClientSecret());

        if (oAuthApplication.getParameter("tokenScope") != null) {
            // properly handle scopes, super implementation expects an array but that will
            // break jagger templates..
            String[] tokenScopes = ((String) oAuthApplication.getParameter("tokenScope")).split(" ");
            tokenRequest.setScope(tokenScopes);
            oAuthApplication.addParameter("tokenScope", Arrays.toString(tokenScopes));
        }

        if (oAuthApplication.getParameter(ApplicationConstants.VALIDITY_PERIOD) != null) {
            tokenRequest.setValidityPeriod(
                    Long.parseLong((String) oAuthApplication.getParameter(ApplicationConstants.VALIDITY_PERIOD)));
        }

        return tokenRequest;

    }

    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {
        this.configuration = configuration;
    }

    /**
     * When provided the ConsumerKey, this method will provide all the Active tokens
     * issued against that Key.
     * 
     * @param consumerKey ConsumerKey of the OAuthClient
     * @return {@link java.util.Set} having active access tokens.
     * @throws APIManagementException
     */
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) throws APIManagementException {
        ApiMgtDAO apiMgtDAO = ApiMgtDAO.getInstance();
        return apiMgtDAO.getActiveTokensOfConsumerKey(consumerKey);
    }

    /**
     * Gives details of the Access Token to be displayed on Store.
     * 
     * @param consumerKey
     * @return {@link org.wso2.carbon.apimgt.api.model.AccessTokenInfo} populating
     *         all the details of the Access Token.
     * @throws APIManagementException
     */
    public AccessTokenInfo getAccessTokenByConsumerKey(String consumerKey) throws APIManagementException {
        return null;
    }

//    /*
//     * Persist tokens in apim
//     * direct connection to DB
//     */
//    private String insertAccessTokenForApp(int clientId, String user, String token) throws SQLException {
//        Connection conn = null;
//        ResultSet rs = null;
//        PreparedStatement ps = null;
//        try {
//            conn = APIMgtDBUtil.getConnection();
//            conn.setAutoCommit(false);
//            String tokenId = UUID.randomUUID().toString();
//            String query = "INSERT INTO IDN_OAUTH2_ACCESS_TOKEN (TOKEN_ID, ACCESS_TOKEN, REFRESH_TOKEN, " +
//                    "CONSUMER_KEY_ID, AUTHZ_USER, TENANT_ID, USER_TYPE, GRANT_TYPE, VALIDITY_PERIOD, " +
//                    "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_STATE,TIME_CREATED,REFRESH_TOKEN_TIME_CREATED) VALUES ('" +
//                    tokenId + "'," + " '" + token + "'," + " 'aa', ?,?, " +
//                    "'-1234','" + APIConstants.ACCESS_TOKEN_USER_TYPE_APPLICATION + "', 'client_credentials', '3600'," +
//                    " '3600', 'ACTIVE','2017-10-17','2017-10-17')";
//            ps = conn.prepareStatement(query);
//            ps.setInt(1, clientId);
//            ps.setString(2, user);
//            ps.executeUpdate();
//            conn.commit();
//            return tokenId;
//        } finally {
//            APIMgtDBUtil.closeAllConnections(ps, conn, rs);
//        }
//    }
//
//    private void deleteAccessTokenForApp(int clientId) throws SQLException {
//        Connection conn = null;
//        ResultSet rs = null;
//        PreparedStatement ps = null;
//        try {
//            conn = APIMgtDBUtil.getConnection();
//            conn.setAutoCommit(false);
//            String query = "DELETE FROM IDN_OAUTH2_ACCESS_TOKEN WHERE CONSUMER_KEY_ID = ?";
//            ps = conn.prepareStatement(query);
//            ps.setInt(1, clientId);
//            ps.executeUpdate();
//            conn.commit();
//        } finally {
//            APIMgtDBUtil.closeAllConnections(ps, conn, rs);
//        }
//    }

    /*
     * Helpers
     */
    protected ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    private String getAdminToken() throws APIManagementException {
        // TODO add cache with expire check + sync
        String adminClientId = configuration.getParameter(ClientConstants.CONFIG_CLIENT_ID);
        String adminClientSecret = configuration.getParameter(ClientConstants.CONFIG_CLIENT_SECRET);

        AccessTokenInfo token = getClientCredentialsToken(adminClientId, adminClientSecret, null);

        if (token == null) {
            throw new APIManagementException("Error generating admin token");
        }

        return token.getAccessToken();

    }

    private AccessTokenInfo getClientCredentialsToken(String clientId, String clientSecret, String[] scopes)
            throws APIManagementException {

        AccessTokenInfo accessTokenInfo = null;

        if (clientId != null && clientSecret != null) {
            log.trace("request token client credentials from AAC for client " + clientId);
            // get endpoint and configure
            String tokenEndpoint = configuration.getParameter(ClientConstants.CONFIG_OAUTH_TOKEN_ENDPOINT);
            URL endpointURL = new URL(tokenEndpoint);
            String endpointProtocol = endpointURL.getProtocol();
            int endpointPort = endpointURL.getPort();

            HttpClient client = APIUtil.getHttpClient(endpointPort, endpointProtocol);
            HttpPost request = new HttpPost(tokenEndpoint);

            // build parameters
            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair(OAuth.OAUTH_GRANT_TYPE, "client_credentials"));
            if (scopes != null) {
                params.add(new BasicNameValuePair(OAuth.OAUTH_SCOPE, String.join(" ", scopes)));
            }

            // pass client auth as basic auth header
            String secret = clientId + ":" + clientSecret;

            request.setHeader(ClientConstants.AUTHORIZATION,
                    ClientConstants.BASIC + " " + Base64.encode(secret.getBytes()));

            try {
                request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

                HttpResponse response = client.execute(request);
                int statusCode = response.getStatusLine().getStatusCode();
                HttpEntity entity = response.getEntity();

                if (statusCode == HttpStatus.SC_OK && entity != null) {
                    // we expect a json
                    JSONObject json = new JSONObject(EntityUtils.toString(entity));

                    if (json != null && json.has(OAuth.OAUTH_ACCESS_TOKEN)) {

                        String accessToken = json.getString(OAuth.OAUTH_ACCESS_TOKEN);
                        String tokenType = json.getString(OAuth.OAUTH_TOKEN_TYPE);
                        long expiresIn = json.getLong(OAuth.OAUTH_EXPIRES_IN);
                        String[] tokenScopes = json.getString(OAuth.OAUTH_SCOPE).split(" ");

                        if (!ClientConstants.BEARER.equals(tokenType)) {
                            throw new APIManagementException(
                                    "Invalid token type received: " + String.valueOf(tokenType));
                        }

                        accessTokenInfo = new AccessTokenInfo();
                        accessTokenInfo.setAccessToken(accessToken);
                        // millis expected
                        accessTokenInfo.setValidityPeriod(expiresIn * 1000);
                        accessTokenInfo.setScope(tokenScopes);
                        accessTokenInfo.setConsumerKey(clientId);
                        accessTokenInfo.setTokenValid(true);
                    } else {
                        log.warn("Access Token Null");
                    }

                } else {
                    handleException("Something went wrong while generating the Access Token");
                }
            } catch (IOException e) {
                log.error("Exception occurred while generating token.", e);
            } catch (JSONException e) {
                log.error("Error occurred while parsing the response.", e);
            }

        } else {
            log.warn("Client Key or Secret not specified");
        }

        return accessTokenInfo;

    }

    private AccessTokenInfo getResourceOwnerToken(String clientId, String clientSecret, String[] scopes,
            String userName, String password)
            throws APIManagementException {

        AccessTokenInfo accessTokenInfo = null;

        if (clientId != null && clientSecret != null && userName != null && password != null) {
            log.trace("request token resource owner from AAC for client " + clientId + " user " + userName);
            // get endpoint and configure
            String tokenEndpoint = configuration.getParameter(ClientConstants.CONFIG_OAUTH_TOKEN_ENDPOINT);
            URL endpointURL = new URL(tokenEndpoint);
            String endpointProtocol = endpointURL.getProtocol();
            int endpointPort = endpointURL.getPort();

            HttpClient client = APIUtil.getHttpClient(endpointPort, endpointProtocol);
            HttpPost request = new HttpPost(tokenEndpoint);

            // build parameters
            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair(OAuth.OAUTH_GRANT_TYPE, "password"));
            if (scopes != null) {
                params.add(new BasicNameValuePair(OAuth.OAUTH_SCOPE, String.join(" ", scopes)));
            }
            params.add(new BasicNameValuePair(OAuth.OAUTH_USERNAME, userName));
            params.add(new BasicNameValuePair(OAuth.OAUTH_PASSWORD, password));

            // pass client auth as basic auth header
            String secret = clientId + ":" + clientSecret;

            request.setHeader(ClientConstants.AUTHORIZATION,
                    ClientConstants.BASIC + " " + Base64.encode(secret.getBytes()));

            try {
                request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

                HttpResponse response = client.execute(request);
                int statusCode = response.getStatusLine().getStatusCode();
                HttpEntity entity = response.getEntity();

                if (statusCode == HttpStatus.SC_OK && entity != null) {
                    // we expect a json
                    JSONObject json = new JSONObject(EntityUtils.toString(entity));

                    if (json != null && json.has(OAuth.OAUTH_ACCESS_TOKEN)) {

                        String accessToken = json.getString(OAuth.OAUTH_ACCESS_TOKEN);
                        String tokenType = json.getString(OAuth.OAUTH_TOKEN_TYPE);
                        long expiresIn = json.getLong(OAuth.OAUTH_EXPIRES_IN);
                        String[] tokenScopes = json.getString(OAuth.OAUTH_SCOPE).split(" ");

                        if (!ClientConstants.BEARER.equals(tokenType)) {
                            throw new APIManagementException(
                                    "Invalid token type received: " + String.valueOf(tokenType));
                        }

                        accessTokenInfo = new AccessTokenInfo();
                        accessTokenInfo.setAccessToken(accessToken);
                        // millis expected
                        accessTokenInfo.setValidityPeriod(expiresIn * 1000);
                        accessTokenInfo.setScope(tokenScopes);
                        accessTokenInfo.setConsumerKey(clientId);
                        accessTokenInfo.setTokenValid(true);

                    } else {
                        log.warn("Access Token Null");
                    }

                } else {
                    handleException("Something went wrong while generating the Access Token");
                }
            } catch (IOException e) {
                log.error("Exception occurred while generating token.", e);
            } catch (JSONException e) {
                log.error("Error occurred while parsing the response.", e);
            }

        } else {
            log.warn("Client Key or Secret not specified");
        }

        return accessTokenInfo;

    }

    
    
    /**
     * common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws org.wso2.carbon.apimgt.api.APIManagementException
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /*
     * Not supported/implemented
     */
    /**
     * This Method will talk to APIResource registration end point of authorization
     * server and creates a new resource
     *
     * @param api                this is a API object which contains all details
     *                           about a API.
     * @param resourceAttributes this param will contains additional details if
     *                           required.
     * @return true if sucessfully registered. false if there is a error while
     *         registering a new resource.
     * @throws APIManagementException
     */

    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    /**
     * This method will be used to retrieve registered resource by given API ID.
     *
     * @param apiId APIM api id.
     * @return It will return a Map with registered resource details.
     * @throws APIManagementException
     */
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }

    /**
     * This method is responsible for update given APIResource by its resourceId.
     *
     * @param api                this is a API object which contains all details
     *                           about a API.
     * @param resourceAttributes this param will contains additional details if
     *                           required.
     * @return TRUE|FALSE. if it is successfully updated it will return TRUE or else
     *         FALSE.
     * @throws APIManagementException
     */
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return false;
    }

    /**
     * This method will accept API id as a parameter and will delete the registered
     * resource.
     *
     * @param apiID API id.
     * @throws APIManagementException
     */
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }

    /**
     * This method will be used to delete mapping records of oAuth applications.
     * 
     * @param consumerKey
     * @throws APIManagementException
     */
    public void deleteMappedApplication(String consumerKey) throws APIManagementException {

    }

}
