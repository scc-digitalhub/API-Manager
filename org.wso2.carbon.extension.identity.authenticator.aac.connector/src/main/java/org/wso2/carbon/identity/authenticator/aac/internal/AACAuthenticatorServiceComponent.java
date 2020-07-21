/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.aac.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.authenticator.aac.AACAuthenticator;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.tenant.mgt.services.TenantMgtAdminService;
import org.wso2.carbon.user.core.service.RealmService;
import java.util.Hashtable;

@Component(
        name = "identity.application.authenticator.AAC.component",
        immediate = true
)
///**
// * @scr.component name="identity.application.authenticator.AAC.component" immediate="true"
// * @scr.reference name="registry.service"
// * interface="org.wso2.carbon.registry.core.service.RegistryService"
// * cardinality="1..1" policy="dynamic" bind="setRegistryService"
// * unbind="unsetRegistryService"
// * @scr.reference name="user.realmservice.default"
// * interface="org.wso2.carbon.user.core.service.RealmService"
// * cardinality="1..1" policy="dynamic" bind="setRealmService"
// * unbind="unsetRealmService"
// */
public class AACAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(AACAuthenticatorServiceComponent.class);
    private BundleContext bundleContext = null;

	
	@Reference(
			name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        log.info("setting Realm Service");
		AACProvisionServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
    	AACProvisionServiceDataHolder.getInstance().setRealmService(null);
    }
    
    public static RealmService getRealmService() {
        return AACProvisionServiceDataHolder.getInstance().getRealmService();
    }  

    @Reference(
            name = "registry.service",
            service = RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
    public void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is set in the AAC Provisioning bundle");
        }
        AACProvisionServiceDataHolder.getInstance().setRegistryService(registryService);
    }

    public static RegistryService getRegistryService() {
        return AACProvisionServiceDataHolder.getInstance().getRegistryService();
    }
    
    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is unset in the AAC Provisioning bundle");
        }
        AACProvisionServiceDataHolder.getInstance().setRegistryService(null);
    }
    
    @Reference(
            name = "tenant.registryloader",
            service = org.wso2.carbon.registry.core.service.TenantRegistryLoader.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetTenantRegistryLoader")
    protected void setTenantRegistryLoader(TenantRegistryLoader tenantRegLoader) {

        AACProvisionServiceDataHolder.getInstance().setTenantRegistryLoader(tenantRegLoader);
    }

    protected void unsetTenantRegistryLoader(TenantRegistryLoader tenantRegLoader) {

    	 AACProvisionServiceDataHolder.getInstance().setTenantRegistryLoader(null);
    }

    public static TenantRegistryLoader getRegistryLoader() {

        return AACProvisionServiceDataHolder.getInstance().getTenantRegistryLoader();
    }
    
//    @Reference(
//            name = "org.wso2.carbon.tenant.mgt",
//            service = org.wso2.carbon.tenant.mgt.services.TenantMgtAdminService.class,
//            cardinality = ReferenceCardinality.MANDATORY,
//            policy = ReferencePolicy.DYNAMIC,
//            unbind = "unsetTenantMgt")
//    protected void setTenantMgt(TenantMgtAdminService tenantmgt) {
//        AACProvisionServiceDataHolder.getInstance().setTenantMgt(tenantmgt);
//    }
//
//    protected void unsetTenantMgt(TenantMgtAdminService tenantRegLoader) {
//
//    	 AACProvisionServiceDataHolder.getInstance().setTenantMgt(null);
//    }
//
//    public static TenantMgtAdminService getTenantMgt() {
//
//        return AACProvisionServiceDataHolder.getInstance().getTenantMgt();
//    }
    
    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            AACAuthenticator authenticator = new AACAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    authenticator, props);
            if (log.isDebugEnabled()) {
                log.debug("AAC authenticator is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating the AAC authenticator ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("AAC authenticator is deactivated");
        }
    }
    
    /**
     * @return
     * @throws FrameworkException
     * @Deprecated The usage of bundle context outside of the component should never be needed. Component should
     * provide necessary wiring for any place which require the BundleContext.
     */
    @Deprecated
    public BundleContext getBundleContext() {

        return bundleContext;
    }

    public void setBundleContext(BundleContext bundleContext) {

        this.bundleContext = bundleContext;
    }
}
