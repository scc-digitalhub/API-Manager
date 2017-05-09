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
import java.util.Calendar;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.springframework.beans.factory.annotation.Value;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceExceptionException;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceStub;
import org.wso2.carbon.tenant.mgt.stub.beans.xsd.TenantInfoBean;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * @author raman
 *
 */
public class TenantManagementService {

	@Value("${api.multitenancy.endpoint}")
	private String mtEndpoint;
	@Value("${api.multitenancy.password}")
	private String password;

	private static final int TIMEOUT_IN_MILLIS = 15 * 60 * 1000;

	private TenantMgtAdminServiceStub mtStub;

	public TenantInfoBean getTenant(String domain) throws AxisFault, RemoteException, TenantMgtAdminServiceExceptionException {
		TenantInfoBean tenant = getMTStub().getTenant(domain);
		if (tenant.getTenantId() == 0) {
			return null;		
		}
		return tenant;
	}

	/**
	 * Create tenant given the domain name and the tenant admin attributes. 
	 * If the tenant already exists for a different user, an exception is thrown.
	 * If the tenant exists it gets updated.
	 * @param domain
	 * @param username
	 * @param password
	 * @param firstName
	 * @param lastName
	 * @return
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws TenantMgtAdminServiceExceptionException
	 */
	public String createTenant(String domain, String username, String password, String firstName, String lastName) throws AxisFault, RemoteException, TenantMgtAdminServiceExceptionException {
		TenantInfoBean bean = new TenantInfoBean();
		bean.setActive(true);
		bean.setAdmin(username);
		bean.setAdminPassword(password);
		bean.setEmail(username);
		bean.setCreatedDate(Calendar.getInstance());
		bean.setFirstname(firstName);
		bean.setLastname(lastName);
		bean.setTenantDomain(domain);
		TenantInfoBean old = getTenant(domain);
		if (old != null && !old.getAdmin().equals(username)) {
			throw new TenantMgtAdminServiceExceptionException("Tenant already exists and is associated to a different admin user");
		} else if (old != null) {
			bean.setTenantId(old.getTenantId());
			bean.setActive(true);
			bean.setOriginatedService(old.getOriginatedService());
			bean.setSuccessKey(old.getSuccessKey());
			bean.setUsagePlan(old.getUsagePlan());
			getMTStub().updateTenant(bean);
			getMTStub().activateTenant(domain);
		} else if (old == null) {
			return getMTStub().addTenant(bean);
		}
		return domain;
	}
	
	/**
	 * Deactivate tenant
	 * @param domain
	 * @throws AxisFault
	 * @throws RemoteException
	 * @throws TenantMgtAdminServiceExceptionException
	 */
	public void deleteTenant(String domain) throws AxisFault, RemoteException, TenantMgtAdminServiceExceptionException {
		if (getTenant(domain) != null) getMTStub().deactivateTenant(domain);
	}
	
	protected TenantMgtAdminServiceStub getMTStub() throws AxisFault {
		if (mtStub == null) {
			mtStub = new TenantMgtAdminServiceStub(null, mtEndpoint);
			CarbonUtils.setBasicAccessSecurityHeaders("admin", password, true, mtStub._getServiceClient());
			ServiceClient client = mtStub._getServiceClient();
			Options options = client.getOptions();
			options.setTimeOutInMilliSeconds(TIMEOUT_IN_MILLIS);
			options.setProperty(HTTPConstants.SO_TIMEOUT, TIMEOUT_IN_MILLIS);
			options.setProperty(HTTPConstants.CONNECTION_TIMEOUT, TIMEOUT_IN_MILLIS);
			options.setCallTransportCleanup(true);
			options.setManageSession(true);
		}
		return mtStub;
	}

	/**
	 * Update tenant data
	 * @param bean
	 * @throws TenantMgtAdminServiceExceptionException 
	 * @throws RemoteException 
	 * @throws AxisFault 
	 */
	public void updateTenant(TenantInfoBean bean) throws AxisFault, RemoteException, TenantMgtAdminServiceExceptionException {
		getMTStub().updateTenant(bean);
	}	
}
