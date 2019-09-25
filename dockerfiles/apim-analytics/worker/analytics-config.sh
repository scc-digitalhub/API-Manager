#!/bin/bash -e

[ -f "./common.sh" ] && . "./common.sh"
#[ -f "./env.properties" ] && . env.properties
# APIM_USER="user"
# APIM_PASS="pass"
# APIM_MYSQL_HOSTNAME="mysql"
# APIM_MYSQL_USER="user"
# APIM_MYSQL_PASS="pass"

# Directory $WSO2HOME/repository/conf
conf_path="${WSO2_SERVER_HOME}/conf/worker"
# Edit properties in api-manager.xml file
conf_file='deployment.yaml'
## WSO2_CARBON_DB
yml_replace 'driverClassName' 'com.mysql.jdbc.Driver' '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'jdbcUrl' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB?useSSL=false" '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'maxPoolSize' '50' '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'password' ${APIM_MYSQL_PASS} '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'username' ${APIM_MYSQL_USER} '[wso2.datasources].dataSources[0].definition.configuration' "${conf_path}/${conf_file}"
## Message_Tracing_DB
yml_replace 'maxPoolSize' '50' '[wso2.datasources].dataSources[3].definition.configuration' "${conf_path}/${conf_file}"
## APIM_ANALYTICS_DB
yml_replace 'driverClassName' 'com.mysql.jdbc.Driver' '[wso2.datasources].dataSources[5].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'jdbcUrl' "jdbc:mysql://${APIM_MYSQL_HOSTNAME}:3306/WSO2AM_COMMON_DB?useSSL=false" '[wso2.datasources].dataSources[5].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'password' ${APIM_MYSQL_PASS} '[wso2.datasources].dataSources[5].definition.configuration' "${conf_path}/${conf_file}"
yml_replace 'username' ${APIM_MYSQL_USER} '[wso2.datasources].dataSources[5].definition.configuration' "${conf_path}/${conf_file}"
## ADD auth.confs
yml_add 'local' '[auth.configs].type' "${conf_path}/${conf_file}"
yml_add 'admin' '[auth.configs].userManager.adminRole' "${conf_path}/${conf_file}"
yml_add 'admin' '[auth.configs].userManager.userStore.users[+].user.username' "${conf_path}/${conf_file}"
APIM_PASS_ENCODED=$(echo -n ${APIM_PASS}|base64)
yml_add ${APIM_PASS_ENCODED} '[auth.configs].userManager.userStore.users[0].user.password' "${conf_path}/${conf_file}"
yml_add '1' '[auth.configs].userManager.userStore.users[0].user.roles' "${conf_path}/${conf_file}"
yml_add '1' '[auth.configs].userManager.userStore.roles[+].role.id' "${conf_path}/${conf_file}"
yml_add ${APIM_USER} '[auth.configs].userManager.userStore.roles[0].role.displayName' "${conf_path}/${conf_file}"
