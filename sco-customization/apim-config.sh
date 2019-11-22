#!/bin/bash -e

[ -f "./common.sh" ] && . "./common.sh"
#[ -f "./env.properties" ] && . env.properties
# APIM_USER="user"
# APIM_PASS="pass"
# APIM_HOSTNAME="wso2apim"
# APIM_REVERSEPROXY="apim.platform.domain.com"
# APIM_GATEWAYENDPOINT="gwapim.platform.domain.com"
# ANALYTICS_HOSTNAME="wso2apim-with-analytics-apim-analytics-service"
# AAC_HOSTNAME="aac"
# AAC_CONSUMERKEY="API_MGT_CLIENT_ID"
# AAC_CONSUMERSECRET="API_MGT_CLIENT_SECRET"
# AAC_REVERSEPROXY="aac.platform.domain.com"
# APIM_MYSQL_HOSTNAME="mysql"
# APIM_MYSQL_USER="user"
# APIM_MYSQL_PASS="pass"

# Directory ${WSO2_SERVER_HOME}/repository/conf
conf_path="${WSO2_SERVER_HOME}/repository/conf"
# Edit properties in api-manager.xml file
conf_file='api-manager.xml'
echo ${conf_file}
xml_replace 'Username' ${APIM_USER} '/APIManager/AuthManager' "${conf_path}/${conf_file}"
xml_replace 'Password' ${APIM_PASS} '/APIManager/AuthManager' "${conf_path}/${conf_file}"
xml_replace 'Username' ${APIM_USER} '/APIManager/APIGateway/Environments/Environment' "${conf_path}/${conf_file}"
xml_replace 'Password' ${APIM_PASS} '/APIManager/APIGateway/Environments/Environment' "${conf_path}/${conf_file}"
xml_replace 'GatewayEndpoint' "http://${APIM_GATEWAYENDPOINT},https://${APIM_GATEWAYENDPOINT}" '/APIManager/APIGateway/Environments/Environment' "${conf_path}/${conf_file}"
xml_replace 'Enabled' 'true' '/APIManager/Analytics' "${conf_path}/${conf_file}"
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
  xml_replace 'KeyManagerClientImpl' 'it.smartcommunitylab.wso2aac.keymanager.AACOAuthClient' '/APIManager/APIKeyManager' "${conf_path}/${conf_file}"
  xml_add 'RegistrationEndpoint' "http://${AAC_HOSTNAME}:8080/aac" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_add 'ConsumerKey' ${AAC_CONSUMERKEY} '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_add 'ConsumerSecret' ${AAC_CONSUMERSECRET} '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_replace 'ServerURL' "https://$APIM_HOSTNAME:9443/services" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_replace 'Username' ${APIM_USER} '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_replace 'Password' ${APIM_PASS} '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_replace 'TokenURL' "http://${AAC_HOSTNAME}:8080/aac/oauth/token" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_replace 'RevokeURL' "https://${APIM_HOSTNAME}:9443/oauth2/revoke" '/APIManager/APIKeyManager/Configuration' "${conf_path}/${conf_file}"
  xml_uncomment 'RemoveOAuthHeadersFromOutMessage' "${conf_path}/${conf_file}"
  xml_replace 'RemoveOAuthHeadersFromOutMessage' 'false' '/APIManager/OAuthConfigurations' "${conf_path}/${conf_file}"
fi
xml_replace 'URL' "${APIM_REVERSEPROXY}/store" '/APIManager/APIStore' "${conf_path}/${conf_file}"
xml_replace 'connectionfactory.TopicConnectionFactory' "amqp://${APIM_USER}:${APIM_PASS}@clientid/carbon?brokerlist='tcp://\${carbon.local.ip}:\${jms.port}'" '/APIManager/ThrottlingConfigurations/JMSConnectionDetails/JMSConnectionParameters' "${conf_path}/${conf_file}"

# Edit properties in carbon.xml file
## xml with default namaspace declaration using underscore _ to match namespace
conf_file='carbon.xml'
echo ${conf_file}
xml_uncomment 'HostName' "${conf_path}/${conf_file}"
xml_uncomment 'MgtHostName' "${conf_path}/${conf_file}"
xml_replace '_:HostName' "${APIM_REVERSEPROXY}" '_:Server' "${conf_path}/${conf_file}"
xml_replace '_:MgtHostName' "${APIM_REVERSEPROXY}" '_:Server' "${conf_path}/${conf_file}"
xml_uncomment 'EnableEmailUserName' "${conf_path}/${conf_file}"

# Edit properties in jndi.properties file
conf_file='jndi.properties'
echo ${conf_file}
prop_replace 'connectionfactory.TopicConnectionFactory' "amqp://${APIM_USER}:${APIM_PASS}@clientid/carbon?brokerlist='tcp://localhost:5672'" "${conf_path}/${conf_file}"
prop_replace 'connectionfactory.QueueConnectionFactory' "amqp://${APIM_USER}:${APIM_PASS}@clientID/test?brokerlist='tcp://localhost:5672'" "${conf_path}/${conf_file}"

# Edit properties in Log4j.properties file
conf_file='log4j.properties'
echo ${conf_file}
prop_replace 'log4j.appender.DAS_AGENT.userName' ${APIM_USER} "${conf_path}/${conf_file}"
prop_replace 'log4j.appender.DAS_AGENT.password' ${APIM_PASS} "${conf_path}/${conf_file}"
prop_replace 'log4j.appender.LOGEVENT.userName' ${APIM_USER} "${conf_path}/${conf_file}"
prop_replace 'log4j.appender.LOGEVENT.password' ${APIM_PASS} "${conf_path}/${conf_file}"

# Edit properties in registry.xml file
conf_file='registry.xml'
echo ${conf_file}
xml_replace 'cacheId' "${APIM_MYSQL_USER}@jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB" '/wso2registry/remoteInstance' "${conf_path}/${conf_file}"


# Edit properties in user-mgt.xml file
conf_file='user-mgt.xml'
echo ${conf_file}
xml_replace 'Password' "${APIM_PASS}" '/UserManager/Realm/Configuration/AdminUser' "${conf_path}/${conf_file}"
xml_replace 'Property[@name="dataSource"]' "jdbc/WSO2UM_DB" '/UserManager/Realm/Configuration' "${conf_path}/${conf_file}"
## xml_add function with attribute
xml_append_elem 'Property' '^[\S]{3,30}$' '/UserManager/Realm/UserStoreManager/Property[@name="UserNameUniqueAcrossTenants"]' "${conf_path}/${conf_file}" 'name=UsernameWithEmailJavaScriptRegEx'

# Directory ${WSO2_SERVER_HOME}/repository/conf/axis2
conf_path="${WSO2_SERVER_HOME}/repository/conf/axis2"
conf_file='axis2.xml'
echo ${conf_file}
## Edit properties in axis2.xml file
### HTTP
xml_append_elem 'parameter' '80' '/axisconfig/transportReceiver[@name="http"]/parameter[@name="non-blocking"]' "${conf_path}/${conf_file}" 'name=proxyPort' 'locked=false'
xml_append_elem 'parameter' "${APIM_GATEWAYENDPOINT}" '/axisconfig/transportReceiver[@name="http"]/parameter[@name="non-blocking"]' "${conf_path}/${conf_file}" 'name=hostname' 'locked=false'
### HTTPS
xml_append_elem 'parameter' '443' '/axisconfig/transportReceiver[@name="https"]/parameter[@name="non-blocking"]' "${conf_path}/${conf_file}" 'name=proxyPort' 'locked=false'
xml_append_elem 'parameter' "${APIM_GATEWAYENDPOINT}" '/axisconfig/transportReceiver[@name="https"]/parameter[@name="non-blocking"]' "${conf_path}/${conf_file}" 'name=hostname' 'locked=false'

# Directory ${WSO2_SERVER_HOME}/repository/conf/datasources
conf_path="${WSO2_SERVER_HOME}/repository/conf/datasources"
conf_file='master-datasources.xml'
echo ${conf_file}
## Edit properties in master-datasources.xml file
### WSO2AM_DB
xml_replace 'url' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_APIMGT_DB?autoReconnect=true&useSSL=false" 'datasources-configuration/datasources/datasource[name="WSO2AM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'username' "${APIM_MYSQL_USER}" 'datasources-configuration/datasources/datasource[name="WSO2AM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'password' "${APIM_MYSQL_PASS}" 'datasources-configuration/datasources/datasource[name="WSO2AM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
### WSO2UM_DB
xml_replace 'url' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB?autoReconnect=true&useSSL=false" 'datasources-configuration/datasources/datasource[name="WSO2UM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'username' "${APIM_MYSQL_USER}" 'datasources-configuration/datasources/datasource[name="WSO2UM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'password' "${APIM_MYSQL_PASS}" 'datasources-configuration/datasources/datasource[name="WSO2UM_DB"]/definition/configuration' "${conf_path}/${conf_file}"
### WSO2REG_DB
xml_replace 'url' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB?autoReconnect=true&useSSL=false" 'datasources-configuration/datasources/datasource[name="WSO2REG_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'username' "${APIM_MYSQL_USER}" 'datasources-configuration/datasources/datasource[name="WSO2REG_DB"]/definition/configuration' "${conf_path}/${conf_file}"
xml_replace 'password' "${APIM_MYSQL_PASS}" 'datasources-configuration/datasources/datasource[name="WSO2REG_DB"]/definition/configuration' "${conf_path}/${conf_file}"

# Directory ${WSO2_SERVER_HOME}/repository/conf/identity
if [ ! -z ${AAC_HOSTNAME} ]; then
  conf_path="${WSO2_SERVER_HOME}/repository/conf/identity"
  conf_file='identity.xml'
  echo ${conf_file}
  ## Edit properties in identity.xmlns
  ## xml with default namaspace declaration using underscore '_:' to match namespace
  #xml_delete '_:GrantTypeName' 'iwa:ntlm' '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType' "${conf_path}/${conf_file}"
  xml_delete '_:GrantTypeName' 'urn:ietf:params:oauth:grant-type:saml2-bearer' '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType' "${conf_path}/${conf_file}"
  xml_replace '_:GrantTypeName' "native" '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType[_:GrantTypeName="iwa:ntlm"]' "${conf_path}/${conf_file}"
  xml_replace '_:GrantTypeValidatorImplClass' 'it.smartcommunitylab.wso2aac.grants.NativeGrantValidator' '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType[_:GrantTypeName="native"]' "${conf_path}/${conf_file}"
  xml_replace '_:GrantTypeHandlerImplClass' 'it.smartcommunitylab.wso2aac.grants.NativeGrantType' '//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType[_:GrantTypeName="native"]' "${conf_path}/${conf_file}"
  xml_replace '@class' 'it.smartcommunitylab.wso2aac.keymanager.CustomJDBCScopeValidator' '//_:Server/_:OAuth/_:OAuthScopeValidator' "${conf_path}/${conf_file}"
fi

# Directory ${WSO2_SERVER_HOME}/repository/deployment/server/jaggeryapps/
conf_path="${WSO2_SERVER_HOME}/repository/deployment/server/jaggeryapps/admin/site/conf"
conf_file='site.json'
echo "admin ${conf_file}"
## Edit properties in admin/site.json
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
  json_replace 'identityProviderURI' "https://${AAC_REVERSEPROXY}/aac" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'authorizationEndpointURI' "https://${AAC_REVERSEPROXY}/aac/oauth/authorize" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'tokenEndpointURI' "https://${AAC_REVERSEPROXY}/aac/oauth/token" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'userInfoURI' "https://${AAC_REVERSEPROXY}/aac/userinfo" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'jwksURI' "https://${AAC_REVERSEPROXY}/aac/jwk" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'logoutEndpointURI' "https://${AAC_REVERSEPROXY}/aac/endsession" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'rolesEndpointURI' "https://${AAC_REVERSEPROXY}/aac/userroles/me" '.oidcConfiguration' "${conf_path}/${conf_file}"
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
  json_replace 'identityProviderURI' "https://${AAC_REVERSEPROXY}/aac" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'authorizationEndpointURI' "https://${AAC_REVERSEPROXY}/aac/oauth/authorize" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'tokenEndpointURI' "https://${AAC_REVERSEPROXY}/aac/oauth/token" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'userInfoURI' "https://${AAC_REVERSEPROXY}/aac/userinfo" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'jwksURI' "https://${AAC_REVERSEPROXY}/aac/jwk" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'logoutEndpointURI' "https://${AAC_REVERSEPROXY}/aac/endsession" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'rolesEndpointURI' "https://${AAC_REVERSEPROXY}/aac/userroles/me" '.oidcConfiguration' "${conf_path}/${conf_file}"
  json_replace 'clientId' ${AAC_CONSUMERKEY} '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'clientSecret' ${AAC_CONSUMERSECRET} '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'redirectURI' "https://${APIM_REVERSEPROXY}/store/jagg/jaggery_oidc_acs.jag" '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
  json_replace 'postLogoutRedirectURI' "https://${APIM_REVERSEPROXY}/store/" '.oidcConfiguration.clientConfiguration' "${conf_path}/${conf_file}"
fi
# Directory ${WSO2_SERVER_HOME}/repository/conf/tomcat
conf_path="${WSO2_SERVER_HOME}/repository/conf/tomcat"
conf_file='catalina-server.xml'
echo ${conf_file}
## Edit properties in catalina-server.xml
xml_append_attr 'Connector[@port="9443"]' "proxyName=${APIM_REVERSEPROXY}" '/Server/Service' "${conf_path}/${conf_file}"
xml_append_attr 'Connector[@port="9443"]' 'proxyPort=443' '/Server/Service' "${conf_path}/${conf_file}"
