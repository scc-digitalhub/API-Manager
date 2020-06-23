package it.smartcommunitylab.wso2aac.provisioning.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "it.smartcommunitylab.wso2aac.provisioning",
        immediate = true
)
public class AACProvisionServiceComponent {

	private static final Log log = LogFactory.getLog(AACProvisionServiceComponent.class);
	
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
    
    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            if (log.isDebugEnabled()) {
                log.debug("AAC Provisioning bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating AAC Provisioning bundle ", e);
        }
    }
}
