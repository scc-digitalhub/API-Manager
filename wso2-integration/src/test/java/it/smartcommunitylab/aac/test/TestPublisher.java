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

package it.smartcommunitylab.aac.test;

import java.rmi.RemoteException;

import org.apache.axis2.AxisFault;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceExceptionException;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceUserStoreExceptionException;

import it.smartcommunitylab.aac.wso2.IntegrationConfig;
import it.smartcommunitylab.aac.wso2.services.TenantManagementService;
import it.smartcommunitylab.aac.wso2.services.UserManagementService;

/**
 * @author raman
 *
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes={TestConfig.class,IntegrationConfig.class})
public class TestPublisher {

	/**
	 * 
	 */
	private static final String TEST_USER = "test1@test-1.com";
	private static final String TEST_DOMAIN = "test.com";
	@Autowired
	private UserManagementService umService;
	@Autowired
	private TenantManagementService tenantService;
	
	@Before
	public void cleanupUser() throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		try {
			if (tenantService.getTenant(TEST_DOMAIN) != null) {
				tenantService.deleteTenant(TEST_DOMAIN);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testCheckTenantExists() throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException, TenantMgtAdminServiceExceptionException {
		Assert.assertTrue(tenantService.getTenant(TEST_DOMAIN) == null || !tenantService.getTenant(TEST_DOMAIN).getActive());
	}

	@Test
	public void testCreatePublisher() throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException, TenantMgtAdminServiceExceptionException {
		umService.createPublsher(TEST_DOMAIN, TEST_USER, "123456", "First", "Last");
		Assert.assertNotNull(tenantService.getTenant(TEST_DOMAIN));
	}
}
