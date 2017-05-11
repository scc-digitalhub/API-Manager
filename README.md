# API-Manager
API Manager tools and themes

# WSO2

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


- in *repository\conf\identity* change


   `<OAuthScopeValidator class="org.wso2.carbon.identity.oauth2.validators.JDBCScopeValidator"/>`

to

   `<OAuthScopeValidator class="it.smartcommunitylab.wso2aac.keymanager.CustomJDBCScopeValidator"/>`

- copy the contents of project *API-Manager/wso2.custom* into the WSO2 directory

- copy *wso2aac.client-1.0.jar* from the project *API-Manager/wso2aac.client* to the WSO2 directory *repository/components/lib*


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

	- launch the following scripts
	 
			mysql -u regadmin -p -Dregdb < dbscripts/mysql.sql
			mysql -u regadmin -p -Dregdb < dbscripts/apimgt/mysql.sql
	

	

		
	     
 