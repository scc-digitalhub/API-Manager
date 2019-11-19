# WSO2 User Management Service

In order to provide the necessary infrastructure for allowing external components to interact with API Manager, it is necessary to include in **repository/components/dropins** the *jar*'s of the following submodules:

	<module>apim.custom.user.store</module>
  	<module>apim.custom.user.store.stub</module>
  	
This extension is done in order to permit the admin account to create, update, delete users and assign/revoke roles within arbitrary tenants and extends the existing [UserStoreManagerService admin](https://github.com/wso2-extensions/identity-user-ws/blob/master/components/org.wso2.carbon.um.ws.service/src/main/java/org/wso2/carbon/um/ws/service/UserStoreManagerService.java).

The configuration steps are the following:
- Build **usermgnt** project with Maven.

- Copy **apim.custom.user.store-XXX.jar** from the project *orgmanager-wso2connector/apim.custom.user.store* to the WSO2 directory **repository/components/dropins**.

- Copy **apim.custom.user.store.stub-XXX.jar** from the project *orgmanager-wso2connector/apim.custom.user.store.stub* to the WSO2 directory **repository/components/dropins**.

As a result, the new admin stub can be accessed from the following end-point: `https://$APIM_URL/services/CustomUserStoreManagerService`

After putting the *jar*'s in the proper folder, you should update the client's configurations:

	usermgmtEndpoint: /services/CustomUserStoreManagerService
