package it.smartcommunitylab.wso2aac.keymanager.service;

import java.rmi.RemoteException;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.xsd.AuthenticationStep;
import org.wso2.carbon.identity.application.common.model.xsd.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.xsd.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceIdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceStub;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceStub;
import org.wso2.carbon.utils.CarbonUtils;

public class SPAdminService {

	private final String identityServiceName = "IdentityApplicationManagementService";
	private final String oauthServiceName = "OAuthAdminService";
	private IdentityApplicationManagementServiceStub identityAdminStub;
	private OAuthAdminServiceStub oauthAdminStub;
	private String identityEndPoint, oauthEndPoint;
	private Log log = LogFactory.getLog(SPAdminService.class);
	private static final int TIMEOUT_IN_MILLIS = 15 * 60 * 1000;

	public SPAdminService(String backEndUrl) {
		this.identityEndPoint = backEndUrl + "/services/" + identityServiceName;
		this.oauthEndPoint = backEndUrl + "/services/" + oauthServiceName;
		try {
//			oauthAdminStub = new OAuthAdminServiceStub(oauthEndPoint);
			identityAdminStub = new IdentityApplicationManagementServiceStub(identityEndPoint);
			CarbonUtils.setBasicAccessSecurityHeaders("admin", "admin", true, identityAdminStub._getServiceClient());
    	    ServiceClient serviceClient = identityAdminStub._getServiceClient();
    	    Options option = serviceClient.getOptions();  
    	    option.setManageSession(true);  
    	    option.setTimeOutInMilliSeconds(TIMEOUT_IN_MILLIS);
    		option.setProperty(HTTPConstants.SO_TIMEOUT, TIMEOUT_IN_MILLIS);
    		option.setProperty(HTTPConstants.CONNECTION_TIMEOUT, TIMEOUT_IN_MILLIS);
    		option.setCallTransportCleanup(true);
    		option.setManageSession(true);
            
			
		} catch (AxisFault e) {
			e.printStackTrace();
		}
	}

	public String updateApplication(String appName) {
		String sessionCookie = null;
		try {
			ServiceProvider serviceProvider = identityAdminStub.getApplication(appName);
			LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig = new LocalAndOutboundAuthenticationConfig();
			IdentityProvider[] identityProviders = new IdentityProvider[1];
			IdentityProvider identityProvider = new IdentityProvider();
			identityProvider.setIdentityProviderName("SHARED_identityProviderIDP_AAC");
			identityProvider.setEnable(true);
			identityProvider.setDisplayName("SHARED_identityProviderIDP_AAC");
//			FederatedAuthenticatorConfig[] federatedConfigs = new FederatedAuthenticatorConfig[1];
//			FederatedAuthenticatorConfig federatedConfig = new FederatedAuthenticatorConfig();
//			
//			federatedConfigs[0] = federatedConfig;
//			identityProvider.setFederatedAuthenticatorConfigs(federatedConfigs);
	        identityProviders[0] = identityProvider;
	        
	        AuthenticationStep[] authenticationSteps = new AuthenticationStep[1];
			AuthenticationStep authenticationStep = new AuthenticationStep();
	        authenticationStep.setStepOrder(1);
	        authenticationStep.setFederatedIdentityProviders(identityProviders);
	        authenticationSteps[0] = authenticationStep;
	        
	        localAndOutboundAuthenticationConfig.setUseTenantDomainInLocalSubjectIdentifier(true);
	        localAndOutboundAuthenticationConfig.setUseUserstoreDomainInLocalSubjectIdentifier(true);
	        localAndOutboundAuthenticationConfig.setUseUserstoreDomainInRoles(true);
	        localAndOutboundAuthenticationConfig.setAuthenticationType("federated");
	        localAndOutboundAuthenticationConfig.setAuthenticationSteps(authenticationSteps);
	        
            serviceProvider.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);
            identityAdminStub.updateApplication(serviceProvider);
            
		} catch (RemoteException e) {
			log.info("Error during SP updateApplication: " + e.getMessage());
		} catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
			e.printStackTrace();
		}
		return sessionCookie;
	}
}