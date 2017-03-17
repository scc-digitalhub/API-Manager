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
import java.util.Arrays;
import java.util.List;

import org.apache.axis2.AxisFault;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.wso2.carbon.um.ws.api.stub.ClaimValue;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceUserStoreExceptionException;

import it.smartcommunitylab.aac.wso2.IntegrationConfig;
import it.smartcommunitylab.aac.wso2.WSO2Constans;
import it.smartcommunitylab.aac.wso2.services.UserManagementService;
import it.smartcommunitylab.aac.wso2.services.Utils;

/**
 * @author raman
 *
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes={TestConfig.class,IntegrationConfig.class})
public class TestUM {

	/**
	 * 
	 */
	private static final String TEST_USER = "test1@test-1.com";

	@Autowired
	private UserManagementService umService;
	
	@Before
	public void cleanupUser() throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		try {
			umService.deleteNormalUser(TEST_USER);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testCheckUserExists() throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		Assert.assertFalse(umService.checkNormalUserExists(TEST_USER));
	}

	@Test
	public void testCreateNewUser() throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		ClaimValue[] claims = new ClaimValue[]{
				Utils.createClaimValue("http://wso2.org/claims/emailaddress", TEST_USER)
		};
		umService.createNormalUser(TEST_USER, "123456", new String[]{"internal/everyone"}, claims);
		Assert.assertTrue(umService.checkNormalUserExists(TEST_USER));
		
		Assert.assertTrue(umService.authenticate(TEST_USER,"123456"));
	}

	@Test
	public void testUpdatePassword() throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		ClaimValue[] claims = new ClaimValue[]{
				Utils.createClaimValue("http://wso2.org/claims/emailaddress", TEST_USER)
		};
		umService.createNormalUser(TEST_USER, "123456", new String[]{"internal/everyone"}, claims);
		Assert.assertTrue(umService.checkNormalUserExists(TEST_USER));

		umService.updateNormalUserPassword(TEST_USER, "654321");
		Assert.assertTrue(umService.checkNormalUserExists(TEST_USER));
	}

	@Test
	public void testCreateSubscriber() throws AxisFault, RemoteException, RemoteUserStoreManagerServiceUserStoreExceptionException {
		ClaimValue[] claims = new ClaimValue[]{
				Utils.createClaimValue("http://wso2.org/claims/emailaddress", TEST_USER)
		};
		umService.createSubscriber(TEST_USER, "123456", claims);
		Assert.assertTrue(umService.checkNormalUserExists(TEST_USER));
		List<String> userRoles = umService.getNormalUserRoles(TEST_USER);
		Assert.assertTrue(userRoles.containsAll(Arrays.asList(WSO2Constans.subscriberRoles())));
	}

}
