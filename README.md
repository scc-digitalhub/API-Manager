# API-Manager
API Manager tools and themes

# WSO2

## Requirements

- AAC
- MySQL 5.5+

## Setup

### 1. Database setup

- using mysql as DB:

		- mysql -u root -p
		
		- create database regdb character set latin1 (*);
		 
		- GRANT ALL ON regdb.* TO regadmin@localhost IDENTIFIED BY "regadmin";
		
		- FLUSH PRIVILEGES;
		 
		- quit;

(*) character set is for windows only

- copy mysql connector (i.e. mysql-connector-java-*-bin.jar) into *repository/components/lib*
	
 
- edit /repository/conf/datasources/master-datasources.xml
	 
	- for the datasources **WSO2_CARBON_DB** and **WSO2AM_DB**, make these changes:
	
			<url>jdbc:mysql://localhost:3306/regdb</url>
            <username>regadmin</username>
            <password>regadmin</password>
            <driverClassName>com.mysql.jdbc.Driver</driverClassName> 

	- launch the following scripts (for MySQL 5.7 use versions *.5.7.sql)
	 
			mysql -u regadmin -p -Dregdb < dbscripts/mysql.sql
			mysql -u regadmin -p -Dregdb < dbscripts/apimgt/mysql.sql

### 2. WSO2 Configuration

Clone API Manager project

**2.1. WSO2-AAC connector**

- build **wso2aac.client** project with Maven.

- copy *wso2aac.client-1.0.jar* from the project *API-Manager/wso2aac.client* to the WSO2 directory *repository/components/lib*

**2.2. WSO2 configurations**

- in *repository/conf/api-manager.xml*, change APIKeyManager and set **ConsumerSecret** with the value found in AAC for the client with clientId API_MGT_CLIENT_ID

    	<APIKeyManager>
    		<KeyManagerClientImpl>it.smartcommunitylab.wso2aac.keymanager.AACOAuthClient</KeyManagerClientImpl>
    		<Configuration>
    			<RegistrationEndpoint>http://localhost:8080/aac</RegistrationEndpoint>
    			<ConsumerKey>API_MGT_CLIENT_ID</ConsumerKey>
    			<ConsumerSecret></ConsumerSecret>
    			<Username>admin</Username>
    			<Password>admin</Password>
    			<VALIDITY_PERIOD>3600</VALIDITY_PERIOD>
    			<ServerURL>https://localhost:9443/services/</ServerURL>
    			<RevokeURL>https://localhost:8243/revoke</RevokeURL>
    			<TokenURL>http://localhost:8080/aac/oauth/token</TokenURL>			
    		</Configuration>
    	</APIKeyManager>


- in *repository\conf\identity\identity.xml* change


   `<OAuthScopeValidator class="org.wso2.carbon.identity.oauth2.validators.JDBCScopeValidator"/>`

to

   `<OAuthScopeValidator class="it.smartcommunitylab.wso2aac.keymanager.CustomJDBCScopeValidator"/>`

**2.3. WSO2 Theming**

- copy the contents of project *API-Manager/wso2.custom* into the WSO2 directory

### 3. Keystore configuration

Import and add WSO2 certificate to the default keystore.

``sudo rm -f cert.pem && sudo echo -n | openssl s_client -connect localhost:9443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ./cert.pem``

``sudo keytool -import -trustcacerts -file cert.pem -alias root -keystore JAVA_HOME/jre/lib/security/cacerts``
	

		
	     
 