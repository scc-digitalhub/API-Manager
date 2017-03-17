/*******************************************************************************
 * Copyright 2015 Fondazione Bruno Kessler
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 ******************************************************************************/

package it.smartcommunitylab.aac.wso2.services;

import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.List;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceStub;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceExceptionException;
import org.wso2.carbon.um.ws.api.stub.ClaimValue;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceStub;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceUserStoreExceptionException;
import org.wso2.carbon.utils.CarbonUtils;

import it.smartcommunitylab.aac.wso2.WSO2Constans;
import it.smartcommunitylab.aac.wso2.model.RoleModel;

/**
 * @author raman
 *
 */
public class UserManagementService {

	@Value("${api.usermgmt.endpoint}")
	private String umEndpoint;
	@Value("${api.usermgmt.password}")
	private String umPassword;

	@Value("${api.identity.endpoint}")
	private String endpoint;
	@Value("${api.identity.password}")
	private String isPassword;
	
	@Autowired
	private TenantManagementService tenantService;
	
	private RemoteUserStoreManagerServiceStub umStub;
	private IdentityApplicationManagementServiceStub iamStub;

	private static final int TIMEOUT_IN_MILLIS = 15 * 60 * 1000;
	
	protected RemoteUserStoreManagerServiceStub getUMStub() throws AxisFault {
		if (umStub == null) {
			umStub = new RemoteUserStoreManagerServiceStub(null, umEndpoint);
			CarbonUtils.setBasicAccessSecurityHeaders("admin", umPassword, true, umStub._getServiceClient());
			ServiceClient client = umStub._getServiceClient();
			Options options = client.getOptions();
			options.setTimeOutInMilliSeconds(TIMEOUT_IN_MILLIS);
			options.setProperty(HTTPConstants.SO_TIMEOUT, TIMEOUT_IN_MILLIS);
			options.setProperty(HTTPConstants.CONNECTION_TIMEOUT, TIMEOUT_IN_MILLIS);
			options.setCallTransportCleanup(true);
			options.setManageSession(true);
		}
		return umStub;
	}
	protected IdentityApplicationManagementServiceStub getIAMStub() throws AxisFault {
		if (iamStub == null) {
			iamStub = new IdentityApplicationManagementServiceStub(null, endpoint);
			CarbonUtils.setBasicAccessSecurityHeaders("admin", isPassword, true, iamStub._getServiceClient());
			ServiceClient client = iamStub._getServiceClient();
			Options options = client.getOptions();
			options.setTimeOutInMilliSeconds(TIMEOUT_IN_MILLIS);
			options.setProperty(HTTPConstants.SO_TIMEOUT, TIMEOUT_IN_MILLIS);
			options.setProperty(HTTPConstants.CONNECTION_TIMEOUT, TIMEOUT_IN_MILLIS);
			options.setCallTransportCleanup(true);
			options.setManageSession(true);
		}
		return iamStub;
	}
	
	/**
	 * Create new user
	 * @param userName
	 * @param password
	 * @param roles
	 * @param claims
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 */
	public void createNormalUser(String userName, String password, String[] roles, ClaimValue[] claims) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		getUMStub().addUser(userName, password, roles, claims, null, false);
	}

	/**
	 * Update user password
	 * @param userName
	 * @param password
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 */
	public void updateNormalUserPassword(String userName, String password) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		getUMStub().updateCredentialByAdmin(userName, password);
	}

	/**
	 * Update publisher password
	 * @param userName
	 * @param domain
	 * @param password
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 */
	public void updatePublisherPassword(String userName, String domain, String password) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		getUMStub().updateCredentialByAdmin(Utils.getUserNameAtTenant(userName, domain), password);
	}

	/**
	 * Create WSO2 API Publisher/creator
	 * @param userName
	 * @param password
	 * @param claims
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 * @throws TenantMgtAdminServiceExceptionException 
	 */
	public void createPublisher(String domain, String userName, String password, String firstName, String lastName) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException, TenantMgtAdminServiceExceptionException {
		tenantService.createTenant(domain, userName, password, firstName, lastName);
	}
	
	/**
	 * Create WSO2 API Subscriber
	 * @param userName
	 * @param password
	 * @param claims
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 */
	public void createSubscriber(String userName, String password, ClaimValue[] claims) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		getUMStub().addUser(userName, password, WSO2Constans.subscriberRoles(), claims, null, false);
	}	
	
	/**
	 * Delete user
	 * @param userName
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 */
	public void deleteNormalUser(String userName) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		getUMStub().deleteUser(userName);
	}
	
	/**
	 * 
	 * @param userName
	 * @return
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException
	 */
	public boolean checkNormalUserExists(String userName) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		return getUMStub().isExistingUser(userName);
	}
	
	/**
	 * @param userName
	 * @param domain the user belongs to
	 * @return List of user roles
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException 
	 * @throws RemoteException 
	 * @throws AxisFault 
	 */
	public List<String> getUserRoles(String userName, String domain) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		return Arrays.asList(getUMStub().getRoleListOfUser(Utils.getUserNameAtTenant(userName, domain)));
	}

	/**
	 * @param userName
	 * @return List of user roles
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException 
	 * @throws RemoteException 
	 * @throws AxisFault 
	 */
	public List<String> getNormalUserRoles(String userName) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		return Arrays.asList(getUMStub().getRoleListOfUser(userName));
	}
	/**
	 * Update user roles from the specified role model
	 * 
	 * @param roleModel
	 * @param username
	 * @param domain
	 * @throws TenantMgtAdminServiceExceptionException 
	 * @throws RemoteException 
	 * @throws AxisFault 
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException 
	 */
	public void updateRoles(RoleModel roleModel, String username, String domain) throws AxisFault, RemoteException, TenantMgtAdminServiceExceptionException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		int tenantId = tenantService.getTenant(domain).getTenantId();
		String[] toDel = null, toAdd = null;
		if (roleModel.getAddRoles() != null && roleModel.getAddRoles().size() > 0) {
			toAdd = new String[roleModel.getAddRoles().size()];
			for (int i = 0; i < toAdd.length; i++) toAdd[i] = fullName(roleModel.getAddRoles().get(i), tenantId);
		}
		if (roleModel.getRemoveRoles() != null && roleModel.getRemoveRoles().size() > 0) {
			toDel = new String[roleModel.getRemoveRoles().size()];
			for (int i = 0; i < toDel.length; i++) toDel[i] = fullName(roleModel.getRemoveRoles().get(i), tenantId);
		}
		if (toAdd != null || toDel != null) {
			getUMStub().updateRoleListOfUser(username, toDel, toAdd);
		} 
	}

	/**
	 * @param username
	 * @param password
	 * @throws RemoteUserStoreManagerServiceUserStoreExceptionException 
	 * @throws RemoteException 
	 * @throws AxisFault 
	 */
	public boolean authenticate(String username, String password) throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		boolean authenticate = getUMStub().authenticate(username, password);
		return authenticate;
	}

	/**
	 * @param string
	 * @param tenantId
	 * @return
	 */
	private String fullName(String string, int tenantId) {
		// TOD check correctness of shared role semantics
		if (tenantId <= 0) return string;
		
		String suffix = "@"+tenantId;
		if (string.endsWith(suffix)) return string;
		return string + suffix;
	}

}
