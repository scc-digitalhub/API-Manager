#!/bin/sh
# ------------------------------------------------------------------------
# Copyright 2018 WSO2, Inc. (http://wso2.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License
# ------------------------------------------------------------------------

set -e

# volume mounts
config_volume=${WORKING_DIRECTORY}/wso2-config-volume
artifact_volume=${WORKING_DIRECTORY}/wso2-artifact-volume
deployment_volume=${WSO2_SERVER_HOME}/repository/deployment/server
# original deployment artifacts
original_deployment_artifacts=${WORKING_DIRECTORY}/wso2-tmp/server
original_h2_databases=${WORKING_DIRECTORY}/wso2-tmp/database
database_volume=${WSO2_SERVER_HOME}/repository/database
# capture Docker container IP from the container's /etc/hosts file
docker_container_ip=$(awk 'END{print $1}' /etc/hosts)

# check if the WSO2 non-root user home exists
test ! -d ${WORKING_DIRECTORY} && echo "WSO2 Docker non-root user home does not exist" && exit 1

# check if the WSO2 product home exists
test ! -d ${WSO2_SERVER_HOME} && echo "WSO2 Docker product home does not exist" && exit 1

# if a deployment_volume is present and empty, copy original deployment artifacts to server...
# copying original artifacts to ${WORKING_DIRECTORY}/wso2-tmp/server was already done in the Dockerfile
# these artifacts will be copied to deployment_volume if it is empty, before the server is started
if test -d ${original_h2_databases}; then
    if [ -z "$(ls -A ${deployment_volume}/)" ]; then
	    # if no artifact is found under <WSO2_SERVER_HOME>/repository/deployment/server; copy originals
	    echo "Copying original deployment artifacts from temporary location to server..."
	    cp -R ${original_deployment_artifacts}/* ${deployment_volume}/
    fi
fi

# copy h2 database if /home/wso2carbon/wso2am-2.6.0/repository/database is empty
if test -d ${original_h2_databases}; then
    if [ -z "$(ls -A ${database_volume}/)" ]; then
	    # if no database is found under ${WORKING_DIRECTORY}/wso2-tmp/database; copy originals
	    echo "Copying original database from temporary location to server..."
	    cp -R ${original_h2_databases}/* ${database_volume}/
    fi
fi

# copy any jaggeryapps changes in persistent storage
test -d ${original_deployment_artifacts}/jaggeryapps/ && cp -RL ${original_deployment_artifacts}/jaggeryapps/* ${deployment_volume}/jaggeryapps/
# copy any configuration changes mounted to config_volume
test -d ${config_volume}/ && cp -RL ${config_volume}/* ${WSO2_SERVER_HOME}/
# copy any artifact changes mounted to artifact_volume
test -d ${artifact_volume}/ && cp -RL ${artifact_volume}/* ${WSO2_SERVER_HOME}/

# make any node specific configuration changes
# for example, set the Docker container IP as the `localMemberHost` under axis2.xml clustering configurations (effective only when clustering is enabled)
sed -i "s#<parameter\ name=\"localMemberHost\".*<\/parameter>#<parameter\ name=\"localMemberHost\">${docker_container_ip}<\/parameter>#" ${WSO2_SERVER_HOME}/repository/conf/axis2/axis2.xml
#import let's encrypt intermediate root ca to client trust store

FILES="./ca/*"
for f in $FILES
do
  filename=$(basename -- "$f")
  filename="${filename%.*}"
  echo "Processing $filename file..."
  keytool -import -alias $filename -file $f -keystore ${WSO2_SERVER_HOME}/repository/resources/security/client-truststore.jks -storepass ${APIM_KEYSTORE_PASS:-wso2carbon} -noprompt
  keytool -list -keystore ${WSO2_SERVER_HOME}/repository/resources/security/client-truststore.jks -alias $filename -storepass ${APIM_KEYSTORE_PASS:-wso2carbon} -noprompt
done

bash apim-config.sh
# start WSO2 Carbon server
sh ${WSO2_SERVER_HOME}/bin/wso2server.sh
