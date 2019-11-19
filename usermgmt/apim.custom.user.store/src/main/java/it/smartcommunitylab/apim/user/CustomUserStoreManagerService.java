package it.smartcommunitylab.apim.user;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.multitenancy.utils.TenantAxisUtils;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.um.ws.service.UserStoreManagerService;
import org.wso2.carbon.um.ws.service.dao.ClaimDTO;
import org.wso2.carbon.um.ws.service.dao.PermissionDTO;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.mgt.common.ClaimValue;

import it.smartcommunitylab.apim.user.internal.CustomUserStoreDSComponent;

/**
 * Custom User admin service class, for the basic functions.
 */
public class CustomUserStoreManagerService extends UserStoreManagerService {
	
	public CustomUserStoreManagerService() throws Exception {
		super();
	}
		
	@Override
	public AxisConfiguration getAxisConfig () {
		String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
		ConfigurationContextService contextService = CustomUserStoreDSComponent.getContextService();
        ConfigurationContext configContext = contextService.getServerConfigContext();
        AxisConfiguration axis = configContext.getAxisConfiguration();
		if(!tenantDomain.equals("carbon.super")) {
	        ConfigurationContext tenantConfigContx = TenantAxisUtils.getTenantConfigurationContext(tenantDomain, configContext);           
	        axis = tenantConfigContx.getAxisConfiguration();
		}
		return axis;
	}
	
	@Override
	public ConfigurationContext getConfigContext() {
		String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
		ConfigurationContextService contextService = CustomUserStoreDSComponent.getContextService();
        ConfigurationContext configContext = contextService.getServerConfigContext();
		if(!tenantDomain.equals("carbon.super")) {
	        configContext = TenantAxisUtils.getTenantConfigurationContext(tenantDomain, configContext);
		}
		return configContext;
	}

	/**
	 * Permits to start/change the tenant context flow
	 * @param tenantId
	 * @param tenantDomain
	 */
	private void startTenantFlow(int tenantId, String tenantDomain) {
		PrivilegedCarbonContext.startTenantFlow();
    	PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
	}
	
	/**
	 * Permits to end the specific tenant flow
	 * @param tenantId
	 * @param tenantDomain
	 */
	private void endTenantFlow() {
		PrivilegedCarbonContext.endTenantFlow();
	}
	
	public void addRole(String arg0, String[] arg1, PermissionDTO[] arg2, int tenantId, String tenantDomain) throws UserStoreException {
		startTenantFlow(tenantId, tenantDomain);
		super.addRole(arg0, arg1, arg2);
		endTenantFlow();
	}

	public void addUser(String userName, String credential, String[] roleList, ClaimValue[] claims, String profileName,
			boolean requirePasswordChange, int tenantId, String tenantDomain) throws UserStoreException {
		startTenantFlow(tenantId, tenantDomain);
		super.addUser(userName, credential, roleList, claims, profileName, requirePasswordChange);
		endTenantFlow();
	}

	public void addUserClaimValue(String userName, String claimURI, String claimValue, String profileName, int tenantId, String tenantDomain)
			throws UserStoreException {
		startTenantFlow(tenantId, tenantDomain);
		super.addUserClaimValue(userName, claimURI, claimValue, profileName);
		endTenantFlow();
	}

	@Override
	public void addUserClaimValues(String arg0, ClaimValue[] arg1, String arg2) throws UserStoreException {
		// TODO Auto-generated method stub
		super.addUserClaimValues(arg0, arg1, arg2);
	}

	@Override
	public boolean authenticate(String userName, String credential) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.authenticate(userName, credential);
	}

	@Override
	public void deleteRole(String roleName) throws UserStoreException {
		// TODO Auto-generated method stub
		super.deleteRole(roleName);
	}

	@Override
	public void deleteUser(String userName) throws UserStoreException {
		// TODO Auto-generated method stub
		super.deleteUser(userName);
	}

	@Override
	public void deleteUserClaimValue(String userName, String claimURI, String profileName) throws UserStoreException {
		// TODO Auto-generated method stub
		super.deleteUserClaimValue(userName, claimURI, profileName);
	}

	@Override
	public void deleteUserClaimValues(String userName, String[] claims, String profileName) throws UserStoreException {
		// TODO Auto-generated method stub
		super.deleteUserClaimValues(userName, claims, profileName);
	}

	@Override
	public String[] getAllProfileNames() throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getAllProfileNames();
	}

	@Override
	public String[] getHybridRoles() throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getHybridRoles();
	}

	@Override
	public long getPasswordExpirationTime(String username) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getPasswordExpirationTime(username);
	}

	@Override
	public String[] getProfileNames(String userName) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getProfileNames(userName);
	}

	@Override
	public String[][] getProperties(Tenant arg0) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getProperties(arg0);
	}

	@Override
	public String[] getRoleListOfUser(String userName) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getRoleListOfUser(userName);
	}

	@Override
	public String[] getRoleNames() throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getRoleNames();
	}

	@Override
	public int getTenantId() throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getTenantId();
	}

	@Override
	public int getTenantIdofUser(String arg0) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getTenantIdofUser(arg0);
	}

	@Override
	public String getUserClaimValue(String userName, String claim, String profileName) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getUserClaimValue(userName, claim, profileName);
	}

	@Override
	public ClaimDTO[] getUserClaimValues(String userName, String profileName) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getUserClaimValues(userName, profileName);
	}

	@Override
	public ClaimValue[] getUserClaimValuesForClaims(String userName, String[] claims, String profileName)
			throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getUserClaimValuesForClaims(userName, claims, profileName);
	}

	@Override
	public int getUserId(String username) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getUserId(username);
	}

	@Override
	public String[] getUserList(String claimUri, String claimValue, String profile) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getUserList(claimUri, claimValue, profile);
	}

	@Override
	public String[] getUserListOfRole(String roleName) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.getUserListOfRole(roleName);
	}

	@Override
	public boolean isExistingRole(String roleName) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.isExistingRole(roleName);
	}

	@Override
	public boolean isExistingUser(String userName) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.isExistingUser(userName);
	}

	@Override
	public boolean isReadOnly() throws UserStoreException {
		// TODO Auto-generated method stub
		return super.isReadOnly();
	}

	@Override
	public String[] listUsers(String filter, int maxItemLimit) throws UserStoreException {
		// TODO Auto-generated method stub
		return super.listUsers(filter, maxItemLimit);
	}

	@Override
	public void setUserClaimValue(String userName, String claimURI, String claimValue, String profileName)
			throws UserStoreException {
		// TODO Auto-generated method stub
		super.setUserClaimValue(userName, claimURI, claimValue, profileName);
	}

	@Override
	public void setUserClaimValues(String userName, ClaimValue[] claims, String profileName) throws UserStoreException {
		// TODO Auto-generated method stub
		super.setUserClaimValues(userName, claims, profileName);
	}

	@Override
	public void updateCredential(String userName, String newCredential, String oldCredential)
			throws UserStoreException {
		// TODO Auto-generated method stub
		super.updateCredential(userName, newCredential, oldCredential);
	}

	@Override
	public void updateCredentialByAdmin(String userName, String newCredential) throws UserStoreException {
		// TODO Auto-generated method stub
		super.updateCredentialByAdmin(userName, newCredential);
	}

	public void updateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles, int tenantId, String tenantDomain)
			throws UserStoreException {
		startTenantFlow(tenantId, tenantDomain);
		super.updateRoleListOfUser(userName, deletedRoles, newRoles);
		endTenantFlow();
	}

	@Override
	public void updateRoleName(String roleName, String newRoleName) throws UserStoreException {
		// TODO Auto-generated method stub
		super.updateRoleName(roleName, newRoleName);
	}

	@Override
	public void updateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers)
			throws UserStoreException {
		// TODO Auto-generated method stub
		super.updateUserListOfRole(roleName, deletedUsers, newUsers);
	}
	
	
}
