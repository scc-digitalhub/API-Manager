/*
*  Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package it.smartcommunitylab.wso2aac.keymanager;

public final class ClientConstants {

    /*
     * Config keys
     */

    public static final String CONFIG_AAC_ENDPOINT = "AACEndpoint";
    public static final String CONFIG_OAUTH_INTROSPECTION_ENDPOINT = "IntrospectionEndpoint";
    public static final String CONFIG_OAUTH_REVOKE_ENDPOINT = "RevokeEndpoint";
    public static final String CONFIG_OAUTH_TOKEN_ENDPOINT = "TokenEndpoint";
    public static final String CONFIG_CLIENT_ID = "ClientId";
    public static final String CONFIG_CLIENT_SECRET = "ClientSecret";

    /*
     * OAuth
     */

    public static final String OAUTH_SUBJECT = "sub";
    public static final String OAUTH_ISSUED_AT = "iat";
    public static final String OAUTH_NOT_BEFORE = "nbf";
    public static final String OAUTH_AUDIENCE = "aud";

    public static final String OAUTH_GRANT_CLIENT_CREDENTIALS = "client_credentials";
    public static final String OAUTH_GRANT_RESOURCE_OWNER = "password";

    /*
     * Constants
     */

    public static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer";
    public static final String BASIC = "Basic";
    public static final String APPLICATION_JSON_CONTENT_TYPE = "application/json";
    public static final String CONTENT_TYPE = "Content-Type";
//    public static final String SCOPES = "scopes";
    public static final String URL_ENCODED_CONTENT_TYPE = "application/x-www-form-urlencoded";
    public static final String CONSUMER_KEY = "ConsumerKey";
    public static final String CONSUMER_SECRET = "ConsumerSecret";
}
