package it.smartcommunitylab.apim.user.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.utils.ConfigurationContextService;

import it.smartcommunitylab.apim.user.CustomUserStoreManagerService;

/**
 * 
 * @scr.reference name="configuration.context.service"
 * interface="org.wso2.carbon.utils.ConfigurationContextService" cardinality="0..1"
 * policy="dynamic" bind="setConfigurationContextService" unbind="unsetConfigurationContextService"
 */
public class CustomUserStoreDSComponent {

	private static ConfigurationContextService contextService;
	private Log log = LogFactory.getLog(CustomUserStoreDSComponent.class);
	
	protected void activate(ComponentContext ctxt) {
        try {
        	log.debug("Custom User Store Manager Bundle started.");
            BundleContext bundleContext = ctxt.getBundleContext();
            bundleContext.registerService(CustomUserStoreManagerService.class.getName(),
                    new CustomUserStoreManagerService(), null);
            log.debug("Custom User Store Manager Bundle activated successfuly.");
        } catch (Throwable e) {
            log.error("Custom User Store Bundle activation Failed.");
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        log.debug("Custom User Store Bundle is deactivated ");
    }
	
	protected void setConfigurationContextService(ConfigurationContextService contextService) {
		CustomUserStoreDSComponent.contextService = contextService;
    }

    protected void unsetConfigurationContextService(ConfigurationContextService contextService) {
    	CustomUserStoreDSComponent.contextService = null;
    }

    public static ConfigurationContextService getContextService() {
        return contextService;
    }
}
