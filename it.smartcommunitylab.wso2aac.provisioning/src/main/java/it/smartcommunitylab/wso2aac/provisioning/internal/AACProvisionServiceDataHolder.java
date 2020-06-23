package it.smartcommunitylab.wso2aac.provisioning.internal;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

public class AACProvisionServiceDataHolder {
    private static AACProvisionServiceDataHolder instance = new AACProvisionServiceDataHolder();
    private RealmService realmService = null;
    private RegistryService registryService = null;

    public static AACProvisionServiceDataHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }
    
    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }
}
