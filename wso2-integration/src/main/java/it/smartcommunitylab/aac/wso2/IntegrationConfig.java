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

package it.smartcommunitylab.aac.wso2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.smartcommunitylab.aac.wso2.services.APIPublisherService;
import it.smartcommunitylab.aac.wso2.services.APIStoreService;
import it.smartcommunitylab.aac.wso2.services.TenantManagementService;
import it.smartcommunitylab.aac.wso2.services.UserManagementService;

/**
 * @author raman
 *
 */
@Configuration
public class IntegrationConfig {

    public @Bean APIStoreService getStore() {
    	return new APIStoreService();
    }
    public @Bean APIPublisherService getPublisher() {
    	return new APIPublisherService();
    }
    public @Bean UserManagementService getUMService() {
    	return new UserManagementService();
    }
    public @Bean TenantManagementService getTenantService() {
    	return new TenantManagementService();
    }
}
