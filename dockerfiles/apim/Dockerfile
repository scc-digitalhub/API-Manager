# syntax=docker/dockerfile:experimental

# ------------------------------------------------------------------------
#
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
#
# ------------------------------------------------------------------------
FROM maven:3-jdk-8 AS build-aac-client
COPY wso2aac.client/src /tmp/src
COPY wso2aac.client/pom.xml /tmp/pom.xml
WORKDIR /tmp/
RUN --mount=type=bind,target=/root/.m2,source=/root/.m2,from=smartcommunitylab/apim-dependency:with_parents mvn package
# RUN mvn package -Dskiptests

FROM maven:3-jdk-8 AS build-usermgmt
COPY usermgmt/apim.custom.user.store/src /tmp/apim.custom.user.store/src
COPY usermgmt/apim.custom.user.store/pom.xml /tmp/apim.custom.user.store/pom.xml
COPY usermgmt/apim.custom.user.store.stub/src /tmp/apim.custom.user.store.stub/src
COPY usermgmt/apim.custom.user.store.stub/pom.xml /tmp/apim.custom.user.store.stub/pom.xml
COPY usermgmt/pom.xml /tmp/pom.xml
WORKDIR /tmp/
RUN --mount=type=bind,target=/root/.m2,source=/root/.m2,from=smartcommunitylab/apim-dependency:with_parents mvn package
# RUN mvn package -Dskiptests

# set base Docker image to AdoptOpenJDK Alpine Docker image
FROM adoptopenjdk/openjdk8:alpine
MAINTAINER WSO2 Docker Maintainers "dev@wso2.org”

# set user configurations
ARG USER=wso2carbon
ARG USER_ID=802
ARG USER_GROUP=wso2
ARG USER_GROUP_ID=802
ARG USER_HOME=/home/${USER}
# set dependant files directory
ARG FILES=./dockerfiles/apim/files
ARG SCO_CUSTOMIZATION=./sco-customization/apim
ARG SCO_CUSTOMIZATION_GLOBAL=./sco-customization/global

# set wso2 product configurations
ARG WSO2_SERVER=wso2am
ARG WSO2_SERVER_VERSION=2.6.0
ARG WSO2_SERVER_PACK=${WSO2_SERVER}-${WSO2_SERVER_VERSION}
ARG WSO2_SERVER_HOME=${USER_HOME}/${WSO2_SERVER_PACK}
ENV ENV=${USER_HOME}"/.ashrc"

# set WSO2 EULA
ARG MOTD='printf "\n\
 Welcome to WSO2 Docker Resources \n\
 --------------------------------- \n\
 This Docker container comprises of a WSO2 product, running with its latest updates \n\
 which are under the End User License Agreement (EULA) 2.0. \n\
 Read more about EULA 2.0 here @ https://wso2.com/licenses/wso2-update/2.0 \n"'

# install required packages
RUN  apk add --update --no-cache \
     curl \
     bash \
     jq \
     xmlstarlet \
     moreutils \
     netcat-openbsd && \
     rm -rf /var/cache/apk/*
RUN wget -q -O /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/2.4.0/yq_linux_amd64" && \
    chmod +x /usr/local/bin/yq
# create a user group and a user
RUN  addgroup -g ${USER_GROUP_ID} ${USER_GROUP}; \
     adduser -u ${USER_ID} -D -g '' -h ${USER_HOME} -G ${USER_GROUP} ${USER} ;

# MOTD login message
RUN echo $MOTD > "$ENV"

# create java prefs dir
# this is to avoid warning logs printed by FileSystemPreferences class
RUN mkdir -p ${USER_HOME}/.java/.systemPrefs && \
    mkdir -p ${USER_HOME}/.java/.userPrefs  && \
    chmod -R 755 ${USER_HOME}/.java && \
    chown -R ${USER}:${USER_GROUP} ${USER_HOME}/.java

# copy wso2 product distribution to user's home directory and set ownership
COPY --chown=wso2carbon:wso2 ${FILES}/${WSO2_SERVER_PACK}/ ${WSO2_SERVER_HOME}/
# copy shared artifacts to a temporary location
COPY --chown=wso2carbon:wso2 ${FILES}/${WSO2_SERVER_PACK}/repository/deployment/server/ ${USER_HOME}/wso2-tmp/server/
# copy init script to user home
COPY --chown=wso2carbon:wso2 ${SCO_CUSTOMIZATION}/init.sh ${USER_HOME}/
COPY --chown=wso2carbon:wso2 ${SCO_CUSTOMIZATION}/apim-config.sh ${USER_HOME}/
COPY --chown=wso2carbon:wso2 ${SCO_CUSTOMIZATION_GLOBAL}/common.sh ${USER_HOME}/
# copy mysql connector jar to the server as a third party library
COPY --chown=wso2carbon:wso2 ${FILES}/mysql-connector-java-*.jar ${WSO2_SERVER_HOME}/repository/components/lib/
# copy smartcommunitylab customization to the server as a thids party library
COPY --chown=wso2carbon:wso2 ${FILES}/ca ${USER_HOME}/ca
COPY --chown=wso2carbon:wso2 --from=build-aac-client /tmp/target/wso2aac.client*.jar ${WSO2_SERVER_HOME}/repository/components/lib/
COPY --chown=wso2carbon:wso2 --from=build-usermgmt /tmp/apim.custom.user.store.stub/target/apim.custom.user.store.stub-*.jar ${WSO2_SERVER_HOME}/repository/components/dropins/
COPY --chown=wso2carbon:wso2 --from=build-usermgmt /tmp/apim.custom.user.store/target/apim.custom.user.store-*.jar ${WSO2_SERVER_HOME}/repository/components/dropins/
# add libraries for Kubernetes membership scheme based clustering
ADD --chown=wso2carbon:wso2 https://repo1.maven.org/maven2/dnsjava/dnsjava/2.1.8/dnsjava-2.1.8.jar ${WSO2_SERVER_HOME}/repository/components/lib/
ADD --chown=wso2carbon:wso2 https://repo1.maven.org/maven2/org/wso2/carbon/kubernetes/artifacts/kubernetes-membership-scheme/1.0.5/kubernetes-membership-scheme-1.0.5.jar ${WSO2_SERVER_HOME}/repository/components/dropins/
# copy scl customization
COPY --chown=wso2carbon:wso2 ${SCO_CUSTOMIZATION}/ ${WSO2_SERVER_HOME}/repository/
COPY --chown=wso2carbon:wso2 ${SCO_CUSTOMIZATION}/conf ${USER_HOME}/wso2-config-volume/repository/conf
COPY --chown=wso2carbon:wso2 ${SCO_CUSTOMIZATION}/deployment/server/ ${USER_HOME}/wso2-tmp/server/
# copy original h2 database (wso2 h2 database autogeneration is not working properly)
COPY --chown=wso2carbon:wso2 ${FILES}/${WSO2_SERVER_PACK}/repository/database/ ${USER_HOME}/wso2-tmp/database/

# set environment variables
ENV WSO2_SERVER_HOME=${WSO2_SERVER_HOME} \
    WORKING_DIRECTORY=${USER_HOME} \
    JAVA_OPTS="-Djava.util.prefs.systemRoot=${USER_HOME}/.java -Djava.util.prefs.userRoot=${USER_HOME}/.java/.userPrefs"

# set the user and work directory
USER ${USER_ID}
WORKDIR ${USER_HOME}

# expose ports
EXPOSE 8280 8243 9763 9443 9099 5672 9711 9611 7711 7611 10397

# initiate container and start WSO2 Carbon server
ENTRYPOINT ["/home/wso2carbon/init.sh"]
