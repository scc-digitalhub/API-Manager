package org.wso2.carbon.identity.authenticator.aac.internal;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.tenant.mgt.services.TenantMgtAdminService;
import org.wso2.carbon.user.core.service.RealmService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

public class AACProvisionServiceDataHolder {
    private static AACProvisionServiceDataHolder instance = new AACProvisionServiceDataHolder();
    private RealmService realmService = null;
    private RegistryService registryService = null;
    private TenantRegistryLoader registryLoader = null;
    private TenantMgtAdminService tenantMgt = null;
    private static final Log log = LogFactory.getLog(AACProvisionServiceDataHolder.class);
    private BundleContext bundleContext = null;
    private List<ApplicationAuthenticator> authenticators = new ArrayList<>();
    private long nanoTimeReference = 0;
    private long unixTimeReference = 0;

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
    
    public TenantRegistryLoader getTenantRegistryLoader() {
        return registryLoader;
    }

    public void setTenantRegistryLoader(TenantRegistryLoader registryLoader) {
        this.registryLoader = registryLoader;
    }
    
    public TenantMgtAdminService getTenantMgt() {
        return tenantMgt;
    }

    public void setTenantMgt(TenantMgtAdminService tenantMgt) {
        this.tenantMgt = tenantMgt;
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

    public List<ApplicationAuthenticator> getAuthenticators() {

        return authenticators;
    }

    public long getNanoTimeReference() {

        return nanoTimeReference;
    }

    private void setNanoTimeReference(long nanoTimeReference) {

        this.nanoTimeReference = nanoTimeReference;
    }

    public long getUnixTimeReference() {

        return unixTimeReference;
    }

    private void setUnixTimeReference(long unixTimeReference) {

        this.unixTimeReference = unixTimeReference;
    }
}
