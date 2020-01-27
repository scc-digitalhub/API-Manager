#!/bin/bash -e

[ -f "./common.sh" ] && . "./common.sh"
#[ -f "./env.properties" ] && . env.properties
# APIM_USER="user"
# APIM_PASS="pass"
# APIM_MYSQL_HOSTNAME="mysql"
# APIM_MYSQL_USER="user"
# APIM_MYSQL_PASS="pass"
# APIM_KEYSTORE_FILENAME=""
# APIM_KEYSTORE_PASS=""
# APIM_KEYSTORE_KEYALIAS=""
# APIM_TRUSTSTORE_FILENAME=""
# APIM_TRUSTSTORE_PASS=""

### Directory $WSO2HOME/repository/conf
conf_path="${WSO2_SERVER_HOME}/conf/worker"
## Edit properties in api-manager.xml file
conf_file='deployment.yaml'
echo ${conf_file}
# WSO2_CARBON_DB
yml_replace 'driverClassName' 'com.mysql.jdbc.Driver' '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'jdbcUrl' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB?useSSL=false" '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'maxPoolSize' '50' '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'password' ${APIM_MYSQL_PASS} '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'username' ${APIM_MYSQL_USER} '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
# Message_Tracing_DB
yml_replace 'maxPoolSize' '50' '[wso2.datasources].dataSources[3].definition.configuration' "${conf_path}/${conf_file}"
# APIM_ANALYTICS_DB
yml_replace 'driverClassName' 'com.mysql.jdbc.Driver' '[wso2.datasources].dataSources[5].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'jdbcUrl' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB?useSSL=false" '[wso2.datasources].dataSources[5].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'password' ${APIM_MYSQL_PASS} '[wso2.datasources].dataSources[5].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'username' ${APIM_MYSQL_USER} '[wso2.datasources].dataSources[5].definition.configuration' "${conf_path}/${conf_file}"
# ADD auth.confs
yml_add 'local' '[auth.configs].type' "${conf_path}/${conf_file}"
yml_add 'admin' '[auth.configs].userManager.adminRole' "${conf_path}/${conf_file}"
yml_add 'admin' '[auth.configs].userManager.userStore.users[+].user.username' "${conf_path}/${conf_file}"
APIM_PASS_ENCODED=$(echo -n ${APIM_PASS}|base64)
yml_add ${APIM_PASS_ENCODED} '[auth.configs].userManager.userStore.users[0].user.password' "${conf_path}/${conf_file}"
yml_add '1' '[auth.configs].userManager.userStore.users[0].user.roles' "${conf_path}/${conf_file}"
yml_add '1' '[auth.configs].userManager.userStore.roles[+].role.id' "${conf_path}/${conf_file}"
yml_add ${APIM_USER} '[auth.configs].userManager.userStore.roles[0].role.displayName' "${conf_path}/${conf_file}"
if [ ! -z ${APIM_KEYSTORE_FILENAME} ]; then
  yml_replace 'keyStoreFile' "\${carbon.home}/resources/security/${APIM_KEYSTORE_FILENAME}" '[wso2.transport.http].listenerConfigurations[1]' "${conf_path}/${conf_file}"
  yml_replace 'keyStorePassword' "${APIM_KEYSTORE_PASS}" '[wso2.transport.http].listenerConfigurations[1]' "${conf_path}/${conf_file}"
  yml_replace 'certPass' "${APIM_KEYSTORE_PASS}" '[wso2.transport.http].listenerConfigurations[1]' "${conf_path}/${conf_file}"
  yml_replace 'keyStoreFile' "\${carbon.home}/resources/security/${APIM_KEYSTORE_FILENAME}" '[siddhi.stores.query.api].listenerConfigurations[1]' "${conf_path}/${conf_file}"
  yml_replace 'keyStorePassword' "${APIM_KEYSTORE_PASS}" '[siddhi.stores.query.api].listenerConfigurations[1]' "${conf_path}/${conf_file}"
  yml_replace 'certPass' "${APIM_KEYSTORE_PASS}" '[siddhi.stores.query.api].listenerConfigurations[1]' "${conf_path}/${conf_file}"
  yml_replace 'keyStoreLocation' "\${sys:carbon.home}/resources/security/${APIM_KEYSTORE_FILENAME}" '[databridge.config]' "${conf_path}/${conf_file}"
  yml_replace 'keyStorePassword' "${APIM_KEYSTORE_PASS}" '[databridge.config]' "${conf_path}/${conf_file}"
  yml_replace 'trustStorePath' "\${sys:carbon.home}/resources/security/${APIM_TRUSTSTORE_FILENAME}" '[data.agent.config].agents[0].agentConfiguration' "${conf_path}/${conf_file}"
  yml_replace 'trustStorePassword' "${APIM_TRUSTSTORE_PASS}" '[data.agent.config].agents[0].agentConfiguration' "${conf_path}/${conf_file}"
  yml_replace 'trustStorePath' "\${sys:carbon.home}/resources/security/${APIM_TRUSTSTORE_FILENAME}" '[data.agent.config].agents[1].agentConfiguration' "${conf_path}/${conf_file}"
  yml_replace 'trustStorePassword' "${APIM_TRUSTSTORE_PASS}" '[data.agent.config].agents[1].agentConfiguration' "${conf_path}/${conf_file}"
  # yml_replace 'privateKeyAlias' "${APIM_KEYSTORE_KEYALIAS}" '[wso2.securevault].secretRepository.parameters' "${conf_path}/${conf_file}"
  ## Edit properties in api-manager.xml file
  # conf_file='master-keys.yaml'
  # echo ${conf_file}
  # APIM_KEYSTORE_PASS_ENCODED=$(echo -n ${APIM_KEYSTORE_PASS}|base64)
  # PSS="!!binary ${APIM_KEYSTORE_PASS_ENCODED}"
  # yml_replace 'keyStorePassword' "${PSS}" 'masterKeys' "${conf_path}/${conf_file}"
  # yml_replace 'privateKeyPassword' "${PSS}" 'masterKeys' "${conf_path}/${conf_file}"
  # sed -i -e s/\'//g "${conf_path}/${conf_file}"
fi
