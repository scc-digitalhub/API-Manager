#!/bin/bash -e

[ -f "./common.sh" ] && . "./common.sh"
#[ -f "./env.properties" ] && . env.properties
# APIM_USER="user"
# APIM_PASS="pass"
# APIM_HOSTNAME="wso2apim"
# APIM_REVERSEPROXY="apim.platform.domain.com"
# APIM_GATEWAYENDPOINT="gwapim.platform.domain.com"
# APIM_KEYSTORE_FILENAME=""
# APIM_KEYSTORE_PASS=""
# APIM_KEYSTORE_KEYALIAS=""
# APIM_TRUSTSTORE_FILENAME=""
# APIM_TRUSTSTORE_PASS=""
# ANALYTICS_HOSTNAME="wso2apim-with-analytics-apim-analytics-service"
# AAC_HOSTNAME="http://aac:8080/aac"
# AAC_REVERSEPROXY="https://aac.platform.local"
# AAC_CONSUMERKEY="API_MGT_CLIENT_ID"
# AAC_CONSUMERSECRET="API_MGT_CLIENT_SECRET"
# APIM_MYSQL_HOSTNAME="mysql"
# APIM_MYSQL_USER="user"
# APIM_MYSQL_PASS="pass"

### Directory ${WSO2_SERVER_HOME}/repository/conf
conf_path="${WSO2_SERVER_HOME}/repository/conf"
## Edit properties in api-manager.xml file
conf_file='api-manager.xml'
echo ${conf_file}
xml_replace 'Username' ${APIM_USER} '/APIManager/AuthManager' "${conf_path}/${conf_file}"
xml_replace 'Password' ${APIM_PASS} '/APIManager/AuthManager' "${conf_path}/${conf_file}"
xml_replace 'Username' ${APIM_USER} '/APIManager/APIGateway/Environments/Environment' "${conf_path}/${conf_file}"
xml_replace 'Password' ${APIM_PASS} '/APIManager/APIGateway/Environments/Environment' "${conf_path}/${conf_file}"
xml_replace 'GatewayEndpoint' "http://${APIM_GATEWAYENDPOINT},https://${APIM_GATEWAYENDPOINT}" '/APIManager/APIGateway/Environments/Environment' "${conf_path}/${conf_file}"
xml_replace 'Enabled' ${ANALYTICS_ENABLED} '/APIManager/Analytics' "${conf_path}/${conf_file}"
xml_replace 'StreamProcessorServerURL' "tcp://${ANALYTICS_HOSTNAME}:7612" '/APIManager/Analytics' "${conf_path}/${conf_file}"
xml_uncomment 'StreamProcessorAuthServerURL' "${conf_path}/${conf_file}"
xml_replace 'StreamProcessorAuthServerURL' "ssl://${ANALYTICS_HOSTNAME}:7712" '/APIManager/Analytics' "${conf_path}/${conf_file}"
xml_replace 'StreamProcessorUsername' ${APIM_USER} '/APIManager/Analytics' "${conf_path}/${conf_file}"
xml_replace 'StreamProcessorPassword' ${APIM_PASS} '/APIManager/Analytics' "${conf_path}/${conf_file}"
xml_replace 'StreamProcessorRestApiURL' "https://${ANALYTICS_HOSTNAME}:7444" '/APIManager/Analytics' "${conf_path}/${conf_file}"
xml_replace 'StreamProcessorRestApiUsername' ${APIM_USER} '/APIManager/Analytics' "${conf_path}/${conf_file}"
xml_replace 'StreamProcessorRestApiPassword' ${APIM_PASS} '/APIManager/Analytics' "${conf_path}/${conf_file}"
if [ ! -z ${AAC_HOSTNAME} ]; then
  xml_uncomment 'APIKeyManager' "${conf_path}/${conf_file}"
  xml_replace 'KeyManagerClientImpl' 'it.smartcommunitylab.wso2aac.keymanager.AACKeymanager' '/APIManager/APIKeyManager' "${conf_path}/${conf_file}"
  xml_add 'AACEndpoint' "${AAC_HOSTNAME}" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_add 'ClientId' ${AAC_CONSUMERKEY} '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_add 'ClientSecret' ${AAC_CONSUMERSECRET} '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_add 'TokenEndpoint' "${AAC_HOSTNAME}/oauth/token" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_add 'RevokeEndpoint' "${AAC_HOSTNAME}/oauth/revoke" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_add 'IntrospectionEndpoint' "${AAC_HOSTNAME}/oauth/introspect" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_replace 'ServerURL' "https://$APIM_HOSTNAME:9443/services" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_replace 'Username' ${APIM_USER} '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_replace 'Password' ${APIM_PASS} '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_comment 'TokenURL' "${conf_path}/${conf_file}"
  xml_comment 'RevokeURL' "${conf_path}/${conf_file}"
  xml_uncomment 'RemoveOAuthHeadersFromOutMessage' "${conf_path}/${conf_file}"
  xml_replace 'RemoveOAuthHeadersFromOutMessage' 'false' '/APIManager/OAuthConfigurations' "${conf_path}/${conf_file}"
fi
xml_replace 'URL' "${APIM_REVERSEPROXY}/store" '/APIManager/APIStore' "${conf_path}/${conf_file}"
xml_replace 'connectionfactory.TopicConnectionFactory' "amqp://${APIM_USER}:${APIM_PASS}@clientid/carbon?brokerlist='tcp://\${carbon.local.ip}:\${jms.port}'" '/APIManager/ThrottlingConfigurations/JMSConnectionDetails/JMSConnectionParameters' "${conf_path}/${conf_file}"
## Edit properties in broker.xml file
conf_file='broker.xml'
echo ${conf_file}
if [ ! -z ${APIM_KEYSTORE_FILENAME} ]; then
  xml_replace 'location' "repository/resources/security/${APIM_KEYSTORE_FILENAME}" '/broker/transports/amqp/sslConnection/keyStore' "${conf_path}/${conf_file}"
  xml_replace 'password' "${APIM_KEYSTORE_PASS}" '/broker/transports/amqp/sslConnection/keyStore' "${conf_path}/${conf_file}"
  xml_replace 'location' "repository/resources/security/${APIM_TRUSTSTORE_FILENAME}" '/broker/transports/amqp/sslConnection/trustStore' "${conf_path}/${conf_file}"
  xml_replace 'password' "${APIM_TRUSTSTORE_PASS}" '/broker/transports/amqp/sslConnection/trustStore' "${conf_path}/${conf_file}"
fi
## Edit properties in carbon.xml file
# xml with default namaspace declaration using underscore _ to match namespace
conf_file='carbon.xml'
echo ${conf_file}
xml_uncomment 'HostName' "${conf_path}/${conf_file}"
xml_uncomment 'MgtHostName' "${conf_path}/${conf_file}"
xml_replace '_:HostName' "${APIM_REVERSEPROXY}" '_:Server' "${conf_path}/${conf_file}"
xml_replace '_:MgtHostName' "${APIM_REVERSEPROXY}" '_:Server' "${conf_path}/${conf_file}"
xml_uncomment 'EnableEmailUserName' "${conf_path}/${conf_file}"
if [ ! -z ${APIM_KEYSTORE_FILENAME} ]; then
  xml_replace '_:Location' "\${carbon.home}/repository/resources/security/${APIM_KEYSTORE_FILENAME}" '_:Server/_:Security/_:KeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:Password' "${APIM_KEYSTORE_PASS}" '_:Server/_:Security/_:KeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:KeyAlias' "${APIM_KEYSTORE_KEYALIAS}" '_:Server/_:Security/_:KeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:KeyPassword' "${APIM_KEYSTORE_PASS}" '_:Server/_:Security/_:KeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:Location' "\${carbon.home}/repository/resources/security/${APIM_KEYSTORE_FILENAME}" '_:Server/_:Security/_:InternalKeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:Password' "${APIM_KEYSTORE_PASS}" '_:Server/_:Security/_:InternalKeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:KeyAlias' "${APIM_KEYSTORE_KEYALIAS}" '_:Server/_:Security/_:InternalKeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:KeyPassword' "${APIM_KEYSTORE_PASS}" '_:Server/_:Security/_:InternalKeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:Location' "\${carbon.home}/repository/resources/security/${APIM_TRUSTSTORE_FILENAME}" '_:Server/_:Security/_:TrustStore' "${conf_path}/${conf_file}"
  xml_replace '_:Password' "${APIM_TRUSTSTORE_PASS}" '_:Server/_:Security/_:TrustStore' "${conf_path}/${conf_file}"
fi
## Edit properties in jndi.properties file
conf_file='jndi.properties'
echo ${conf_file}
prop_replace 'connectionfactory.TopicConnectionFactory' "amqp://${APIM_USER}:${APIM_PASS}@clientid/carbon?brokerlist='tcp://localhost:5672'" "${conf_path}/${conf_file}"
prop_replace 'connectionfactory.QueueConnectionFactory' "amqp://${APIM_USER}:${APIM_PASS}@clientID/test?brokerlist='tcp://localhost:5672'" "${conf_path}/${conf_file}"
## Edit properties in Log4j.properties file
conf_file='log4j.properties'
echo ${conf_file}
prop_replace 'log4j.appender.DAS_AGENT.userName' ${APIM_USER} "${conf_path}/${conf_file}"
prop_replace 'log4j.appender.DAS_AGENT.password' ${APIM_PASS} "${conf_path}/${conf_file}"
prop_replace 'log4j.appender.LOGEVENT.userName' ${APIM_USER} "${conf_path}/${conf_file}"
prop_replace 'log4j.appender.LOGEVENT.password' ${APIM_PASS} "${conf_path}/${conf_file}"
## Edit properties in registry.xml file
conf_file='registry.xml'
echo ${conf_file}
xml_replace 'cacheId' "${APIM_MYSQL_USER}@jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB" '/wso2registry/remoteInstance' "${conf_path}/${conf_file}"
## Edit properties in user-mgt.xml file
conf_file='user-mgt.xml'
echo ${conf_file}
xml_replace 'Password' "${APIM_PASS}" '/UserManager/Realm/Configuration/AdminUser' "${conf_path}/${conf_file}"
xml_replace 'Property[@name="dataSource"]' "jdbc/WSO2UM_DB" '/UserManager/Realm/Configuration' "${conf_path}/${conf_file}"
# xml_add function with attribute
xml_append_elem 'Property' '^[\S]{3,30}$' '/UserManager/Realm/UserStoreManager/Property[@name="UserNameUniqueAcrossTenants"]' "${conf_path}/${conf_file}" 'name=UsernameWithEmailJavaScriptRegEx'

### Directory ${WSO2_SERVER_HOME}/repository/conf/axis2
conf_path="${WSO2_SERVER_HOME}/repository/conf/axis2"
## Edit properties in axis2.xml file
conf_file='axis2.xml'
echo ${conf_file}
# HTTP
xml_append_elem 'parameter' '80' '/axisconfig/transportReceiver[@name="http"]/parameter[@name="non-blocking"]' "${conf_path}/${conf_file}" 'name=proxyPort' 'locked=false'
xml_append_elem 'parameter' "${APIM_GATEWAYENDPOINT}" '/axisconfig/transportReceiver[@name="http"]/parameter[@name="non-blocking"]' "${conf_path}/${conf_file}" 'name=hostname' 'locked=false'
# HTTPS
xml_append_elem 'parameter' '443' '/axisconfig/transportReceiver[@name="https"]/parameter[@name="non-blocking"]' "${conf_path}/${conf_file}" 'name=proxyPort' 'locked=false'
xml_append_elem 'parameter' "${APIM_GATEWAYENDPOINT}" '/axisconfig/transportReceiver[@name="https"]/parameter[@name="non-blocking"]' "${conf_path}/${conf_file}" 'name=hostname' 'locked=false'
if [ ! -z ${APIM_KEYSTORE_FILENAME} ]; then
  # transportReceiver
  xml_replace 'Location' "repository/resources/security/${APIM_KEYSTORE_FILENAME}" '/axisconfig/transportReceiver[@name="https"]/parameter[@name="keystore"]/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'Password' "${APIM_KEYSTORE_PASS}" '/axisconfig/transportReceiver[@name="https"]/parameter[@name="keystore"]/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'KeyPassword' "${APIM_KEYSTORE_PASS}" '/axisconfig/transportReceiver[@name="https"]/parameter[@name="keystore"]/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'Location' "repository/resources/security/${APIM_TRUSTSTORE_FILENAME}" '/axisconfig/transportReceiver[@name="https"]/parameter[@name="truststore"]/TrustStore' "${conf_path}/${conf_file}"
  xml_replace 'Password' "${APIM_TRUSTSTORE_PASS}" '/axisconfig/transportReceiver[@name="https"]/parameter[@name="truststore"]/TrustStore' "${conf_path}/${conf_file}"
  # transportSender
  xml_replace 'Location' "repository/resources/security/${APIM_KEYSTORE_FILENAME}" '/axisconfig/transportSender[@name="https"]/parameter[@name="keystore"]/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'Password' "${APIM_KEYSTORE_PASS}" '/axisconfig/transportSender[@name="https"]/parameter[@name="keystore"]/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'KeyPassword' "${APIM_KEYSTORE_PASS}" '/axisconfig/transportSender[@name="https"]/parameter[@name="keystore"]/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'Location' "repository/resources/security/${APIM_TRUSTSTORE_FILENAME}" '/axisconfig/transportSender[@name="https"]/parameter[@name="truststore"]/TrustStore' "${conf_path}/${conf_file}"
  xml_replace 'Password' "${APIM_TRUSTSTORE_PASS}" '/axisconfig/transportSender[@name="https"]/parameter[@name="truststore"]/TrustStore' "${conf_path}/${conf_file}"
  xml_replace 'ws.trust.store.location' "repository/resources/security/${APIM_TRUSTSTORE_FILENAME}" '/axisconfig/transportSender[@name="wss"]/parameter[@name="ws.trust.store"]' "${conf_path}/${conf_file}"
  xml_replace 'ws.trust.store.Password' "${APIM_TRUSTSTORE_PASS}" '/axisconfig/transportSender[@name="wss"]/parameter[@name="ws.trust.store"]' "${conf_path}/${conf_file}"
fi

### Directory ${WSO2_SERVER_HOME}/repository/conf/data-bridge
conf_path="${WSO2_SERVER_HOME}/repository/conf/data-bridge"
## Edit properties in data-bridge-config.xml file
conf_file='data-bridge-config.xml'
if [ ! -z ${APIM_KEYSTORE_FILENAME} ]; then
  echo ${conf_file}
  xml_replace 'keyStoreLocation' "\${carbon.home}/repository/resources/security/${APIM_KEYSTORE_FILENAME}" '/dataBridgeConfiguration' "${conf_path}/${conf_file}"
  xml_replace 'keyStorePassword' "${APIM_KEYSTORE_PASS}" '/dataBridgeConfiguration' "${conf_path}/${conf_file}"
fi

### Directory ${WSO2_SERVER_HOME}/repository/conf/datasources
conf_path="${WSO2_SERVER_HOME}/repository/conf/datasources"
## Edit properties in master-datasources.xml file
conf_file='master-datasources.xml'
echo ${conf_file}
# WSO2AM_DB
xml_replace 'url' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_APIMGT_DB?autoReconnect=true&useSSL=false" 'datasources-configuration/datasources/datasource[name="WSO2AM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'username' "${APIM_MYSQL_USER}" 'datasources-configuration/datasources/datasource[name="WSO2AM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'password' "${APIM_MYSQL_PASS}" 'datasources-configuration/datasources/datasource[name="WSO2AM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
# WSO2UM_DB
xml_replace 'url' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB?autoReconnect=true&useSSL=false" 'datasources-configuration/datasources/datasource[name="WSO2UM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'username' "${APIM_MYSQL_USER}" 'datasources-configuration/datasources/datasource[name="WSO2UM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'password' "${APIM_MYSQL_PASS}" 'datasources-configuration/datasources/datasource[name="WSO2UM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
# WSO2REG_DB
xml_replace 'url' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB?autoReconnect=true&useSSL=false" 'datasources-configuration/datasources/datasource[name="WSO2REG_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'username' "${APIM_MYSQL_USER}" 'datasources-configuration/datasources/datasource[name="WSO2REG_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'password' "${APIM_MYSQL_PASS}" 'datasources-configuration/datasources/datasource[name="WSO2REG_DB"]/definition/configuration' "${conf_path}/${conf_file}"

### Directory ${WSO2_SERVER_HOME}/repository/conf/identity
conf_path="${WSO2_SERVER_HOME}/repository/conf/identity"
## Edit properties in identity.xmln
conf_file='identity.xml'
echo ${conf_file}
if [ ! -z ${AAC_HOSTNAME} ]; then
  # xml with default namaspace declaration using underscore '_:' to match namespace
  xml_delete '_:GrantTypeName' 'iwa:ntlm' '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType' "${conf_path}/${conf_file}"
  xml_delete '_:GrantTypeName' 'urn:ietf:params:oauth:grant-type:saml2-bearer' '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType' "${conf_path}/${conf_file}"
  xml_replace '_:GrantTypeName' "native" '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType[_:GrantTypeName="iwa:ntlm"]' "${conf_path}/${conf_file}"
  xml_replace '_:GrantTypeValidatorImplClass' 'it.smartcommunitylab.wso2aac.grants.NativeGrantValidator' '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType[_:GrantTypeName="native"]' "${conf_path}/${conf_file}"
  xml_replace '_:GrantTypeHandlerImplClass' 'it.smartcommunitylab.wso2aac.grants.NativeGrantType' '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType[_:GrantTypeName="native"]' "${conf_path}/${conf_file}"
  xml_replace '@class' 'it.smartcommunitylab.wso2aac.keymanager.CustomJDBCScopeValidator' '//_:Server/_:OAuth/_:OAuthScopeValidator' "${conf_path}/${conf_file}"
  xml_replace '_:IdentityOAuthTokenGenerator' 'it.smartcommunitylab.wso2aac.keymanager.AACTokenIssuer' '//_:Server/_:OAuth' "${conf_path}/${conf_file}"
fi
if [ ! -z ${APIM_KEYSTORE_FILENAME} ]; then
  xml_replace '_:Location' "\${carbon.home}/repository/resources/security/${APIM_KEYSTORE_FILENAME}" '//_:Server/_:EntitlementSettings/_:ThirftBasedEntitlementConfig/_:KeyStore' "${conf_path}/${conf_file}"
  xml_replace '_:Password' "${APIM_KEYSTORE_PASS}" '//_:Server/_:EntitlementSettings/_:ThirftBasedEntitlementConfig/_:KeyStore' "${conf_path}/${conf_file}"
  ## Edit properties in EndpointConfig.properties
  conf_file='EndpointConfig.properties'
  echo ${conf_file}
  prop_replace 'client.keyStore' "./repository/resources/security/${APIM_KEYSTORE_FILENAME}" "${conf_path}/${conf_file}"
  prop_replace 'Carbon.Security.KeyStore.Password' "${APIM_KEYSTORE_PASS}" "${conf_path}/${conf_file}"
  prop_replace 'client.trustStore' "./repository/resources/security/${APIM_TRUSTSTORE_FILENAME}" "${conf_path}/${conf_file}"
  prop_replace 'Carbon.Security.TrustStore.Password' "${APIM_TRUSTSTORE_PASS}" "${conf_path}/${conf_file}"
fi

### Directory ${WSO2_SERVER_HOME}/repository/deployment/server/jaggeryapps/
conf_path="${WSO2_SERVER_HOME}/repository/deployment/server/jaggeryapps/admin/site/conf"
## Edit properties in admin/site.json
conf_file='site.json'
echo "admin ${conf_file}"
json_replace 'enabled' 'true' '.reverseProxy' "${conf_path}/${conf_file}"
json_replace 'host' ${APIM_REVERSEPROXY} '.reverseProxy' "${conf_path}/${conf_file}"
json_replace 'context' '/admin' '.reverseProxy' "${conf_path}/${conf_file}"
json_add 'whiteListedHostNames' ${APIM_REVERSEPROXY} '' "${conf_path}/${conf_file}"
## Edit properties in publisher/site.json
conf_path="${WSO2_SERVER_HOME}/repository/deployment/server/jaggeryapps/publisher/site/conf"
conf_file='site.json'
echo "publisher ${conf_file}"
json_replace 'enabled' 'true' '.reverseProxy' "${conf_path}/${conf_file}"
json_replace 'host' ${APIM_REVERSEPROXY} '.reverseProxy' "${conf_path}/${conf_file}"
json_replace 'context' '/publisher' '.reverseProxy' "${conf_path}/${conf_file}"
if [ ! -z ${AAC_HOSTNAME} ]; then
  json_replace 'enabled' 'true' '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'identityProviderURI' "${AAC_REVERSEPROXY}" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'authorizationEndpointURI' "${AAC_REVERSEPROXY}/oauth/authorize" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'tokenEndpointURI' "${AAC_HOSTNAME}/oauth/token" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'userInfoURI' "${AAC_HOSTNAME}/userinfo" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'jwksURI' "${AAC_HOSTNAME}/jwk" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'logoutEndpointURI' "${AAC_REVERSEPROXY}/endsession" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'rolesEndpointURI' "${AAC_HOSTNAME}/userroles/me" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'clientId' ${AAC_CONSUMERKEY} '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'clientSecret' ${AAC_CONSUMERSECRET} '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'redirectURI' "https://${APIM_REVERSEPROXY}/publisher/jagg/jaggery_oidc_acs.jag" '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'postLogoutRedirectURI' "https://${APIM_REVERSEPROXY}/store/" '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
fi
## Edit properties in store/site.json
conf_path="${WSO2_SERVER_HOME}/repository/deployment/server/jaggeryapps/store/site/conf"
conf_file='site.json'
echo "store ${conf_file}"
json_replace 'enabled' 'true' '.reverseProxy' "${conf_path}/${conf_file}"
json_replace 'host' ${APIM_REVERSEPROXY} '.reverseProxy' "${conf_path}/${conf_file}"
json_replace 'context' '/store' '.reverseProxy' "${conf_path}/${conf_file}"
if [ ! -z ${AAC_HOSTNAME} ]; then
  json_replace 'enabled' 'true' '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'identityProviderURI' "${AAC_REVERSEPROXY}" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'authorizationEndpointURI' "${AAC_REVERSEPROXY}/oauth/authorize" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'tokenEndpointURI' "${AAC_HOSTNAME}/oauth/token" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'userInfoURI' "${AAC_HOSTNAME}/userinfo" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'jwksURI' "${AAC_HOSTNAME}/jwk" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'logoutEndpointURI' "${AAC_REVERSEPROXY}/endsession" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'rolesEndpointURI' "${AAC_HOSTNAME}/userroles/me" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'clientId' ${AAC_CONSUMERKEY} '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'clientSecret' ${AAC_CONSUMERSECRET} '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'redirectURI' "https://${APIM_REVERSEPROXY}/store/jagg/jaggery_oidc_acs.jag" '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'postLogoutRedirectURI' "https://${APIM_REVERSEPROXY}/store/" '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
fi

### Directory ${WSO2_SERVER_HOME}/repository/resources/security
if [ ! -z ${APIM_KEYSTORE_FILENAME} ]; then
  conf_path="${WSO2_SERVER_HOME}/repository/resources/security"
  ## Edit properties in sslprofiles.xml
  conf_file='sslprofiles.xml'
  echo ${conf_file}
  xml_replace 'Location' "repository/resources/security/${APIM_KEYSTORE_FILENAME}" '/parameter[@name="customSSLProfiles"]/profile/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'Password' "${APIM_KEYSTORE_PASS}" '/parameter[@name="customSSLProfiles"]/profile/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'KeyPassword' "${APIM_KEYSTORE_PASS}" '/parameter[@name="customSSLProfiles"]/profile/KeyStore' "${conf_path}/${conf_file}"
  xml_replace 'Location' "repository/resources/security/${APIM_TRUSTSTORE_FILENAME}" '/parameter[@name="customSSLProfiles"]/profile/TrustStore' "${conf_path}/${conf_file}"
  xml_replace 'Password' "${APIM_TRUSTSTORE_PASS}" '/parameter[@name="customSSLProfiles"]/profile/TrustStore' "${conf_path}/${conf_file}"
fi
### Directory ${WSO2_SERVER_HOME}/repository/conf/tomcat
conf_path="${WSO2_SERVER_HOME}/repository/conf/tomcat"
## Edit properties in catalina-server.xml
conf_file='catalina-server.xml'
echo ${conf_file}
xml_append_attr 'Connector[@port="9443"]' "proxyName=${APIM_REVERSEPROXY}" '/Server/Service' "${conf_path}/${conf_file}"
xml_append_attr 'Connector[@port="9443"]' 'proxyPort=443' '/Server/Service' "${conf_path}/${conf_file}"
if [ ! -z ${APIM_KEYSTORE_FILENAME} ]; then
  xml_replace '@keystoreFile' "\${carbon.home}/repository/resources/security/${APIM_KEYSTORE_FILENAME}" '/Server/Service/Connector[@port="9443"]' "${conf_path}/${conf_file}"
  xml_replace '@keystorePass' "${APIM_KEYSTORE_PASS}" '/Server/Service/Connector[@port="9443"]' "${conf_path}/${conf_file}"
fi
