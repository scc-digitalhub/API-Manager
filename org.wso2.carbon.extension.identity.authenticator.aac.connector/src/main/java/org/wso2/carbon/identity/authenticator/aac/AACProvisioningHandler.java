package org.wso2.carbon.identity.authenticator.aac;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.caching.impl.Util;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.multitenancy.utils.TenantAxisUtils;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.core.util.PermissionUpdateUtil;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.handler.provisioning.ProvisioningHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.impl.UserSessionManagementServiceImpl;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.mgt.cache.IdentityServiceProviderCache;
import org.wso2.carbon.identity.application.mgt.cache.IdentityServiceProviderCacheKey;
import org.wso2.carbon.identity.authenticator.aac.internal.AACAuthenticatorServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.tenant.resource.manager.TenantAwareAxis2ConfigurationContextObserver;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.constant.FederatedAssociationConstants;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.tenant.mgt.services.TenantMgtAdminService;
import org.wso2.carbon.tenant.mgt.util.TenantMgtUtil;
import org.wso2.carbon.user.api.Permission;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.TenantMgtConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.AuthenticationObserver;
import org.wso2.carbon.utils.Axis2ConfigurationContextObserver;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants
        .InternalRoleDomains.APPLICATION_DOMAIN;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants
        .InternalRoleDomains.WORKFLOW_DOMAIN;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;


public class AACProvisioningHandler{

	    private static final Log log = LogFactory.getLog(AACProvisioningHandler.class);
	    private static final String ALREADY_ASSOCIATED_MESSAGE = "UserAlreadyAssociated";
	    private static volatile AACProvisioningHandler instance;
	    private SecureRandom random = new SecureRandom();
	    private static TenantRegistryLoader tenantRegistryLoader;

	    public static AACProvisioningHandler getInstance() {
	        if (instance == null) {
	            synchronized (AACProvisioningHandler.class) {
	                if (instance == null) {
	                    instance = new AACProvisioningHandler();
	                }
	            }
	        }
	        return instance;
	    }

	    public void handle(List<String> roles, String subject, Map<String, String> attributes,
	                       String provisioningUserStoreId, String tenantDomain) throws FrameworkException {

	        log.info(subject + " " + tenantDomain);
	        if(subject.equals("admin@carbon.super"))
	        	return;
	        RegistryService registryService = AACAuthenticatorServiceComponent.getRegistryService();
	        RealmService realmService = AACAuthenticatorServiceComponent.getRealmService();
	        String username = MultitenantUtils.getTenantAwareUsername(subject);
	        String password = generatePassword();
	        try {
	        	int tenantId = provisionTenant(subject, tenantDomain, password);
	            UserRealm realm = AnonymousSessionUtil.getRealmByTenantDomain(registryService, realmService, tenantDomain);
	            String userStoreDomain;
	            UserStoreManager userStoreManager;
                String userStoreDomainFromSubject = UserCoreUtil.extractDomainFromName(subject);
                try {
                    userStoreManager = getUserStoreManager(realm, userStoreDomainFromSubject);
                    userStoreDomain = userStoreDomainFromSubject;
                } catch (FrameworkException e) {
                    log.error("User store domain " + userStoreDomainFromSubject + " does not exist for the tenant "
                            + tenantDomain + ", hence provisioning user to "
                            + UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
                    userStoreDomain = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
                    userStoreManager = getUserStoreManager(realm, userStoreDomain);
                }
	            
	            username = UserCoreUtil.removeDomainFromName(username);

	            if (log.isDebugEnabled()) {
	                log.debug("User: " + username + " with roles : " + roles + " is going to be provisioned");
	            }

	            // If internal roles exists convert internal role domain names to pre defined camel case domain names.
	            List<String> rolesToAdd  = convertInternalRoleDomainsToCamelCase(roles);
	            log.info(rolesToAdd.toString());

	            String idp = attributes.remove(FrameworkConstants.IDP_ID);
	            String subjectVal = attributes.remove(FrameworkConstants.ASSOCIATED_ID);

	            Map<String, String> userClaims = prepareClaimMappings(attributes);

	            if (userStoreManager.isExistingUser(username)) {
	                if (!userClaims.isEmpty()) {
	                    userClaims.remove(FrameworkConstants.PASSWORD);
	                    userClaims.remove(USERNAME_CLAIM);
	                    userStoreManager.setUserClaimValues(UserCoreUtil.removeDomainFromName(username), userClaims, null);
	                }
//	                String associatedUserName = FrameworkUtils.getFederatedAssociationManager()
//	                        .getUserForFederatedAssociation(tenantDomain, idp, subjectVal);
//	                if (StringUtils.isEmpty(associatedUserName)) {
//	                    // Associate User
//	                    associateUser(username, userStoreDomain, tenantDomain, subjectVal, idp);
//	                }
	            } else {
	                String passwordFromUser = userClaims.get(FrameworkConstants.PASSWORD);
	                if (StringUtils.isNotEmpty(passwordFromUser)) {
	                    password = passwordFromUser;
	                }

	                // Check for inconsistencies in username attribute and the username claim.
	                if (userClaims.containsKey(USERNAME_CLAIM) && !userClaims.get(USERNAME_CLAIM).equals(username)) {
	                    // If so update the username claim with the username attribute.
	                    userClaims.put(USERNAME_CLAIM, username);
	                }

	                userClaims.remove(FrameworkConstants.PASSWORD);
	                userStoreManager.addUser(username, password, null, userClaims, null);
	                
	                // Associate User
//	                associateUser(username, userStoreDomain, tenantDomain, subjectVal, idp);

	                if (log.isDebugEnabled()) {
	                    log.debug("Federated user: " + username + " is provisioned by authentication framework.");
	                }
	            }

	            if (roles != null && !roles.isEmpty()) {
	            	if(!tenantDomain.equals("carbon.super"))
	            		roleProvisioning(userStoreManager, tenantDomain);
	            	// Update user with roles
	                List<String> currentRolesList = Arrays.asList(userStoreManager.getRoleListOfUser(username));
	                Collection<String> deletingRoles = retrieveRolesToBeDeleted(realm, currentRolesList, rolesToAdd);
	                rolesToAdd.removeAll(currentRolesList);

	                // TODO : Does it need to check this?
	                // Check for case whether superadmin login
	                handleFederatedUserNameEqualsToSuperAdminUserName(realm, username, userStoreManager, deletingRoles);

	                updateUserWithNewRoleSet(username, userStoreManager, rolesToAdd, deletingRoles, tenantDomain, password);
	            }
	            PermissionUpdateUtil.updatePermissionTree(tenantId);

	        } catch (org.wso2.carbon.user.api.UserStoreException | CarbonException e) {
	            throw new FrameworkException("Error while provisioning user : " + subject, e);
	        } catch (Exception e) {
				throw new FrameworkException("Error during tenant creation", e);
			} finally {
	            IdentityUtil.clearIdentityErrorMsg();
	        }
	    }

	    protected void associateUser(String username, String userStoreDomain, String tenantDomain, String subject,
	                                 String idp) throws FrameworkException {

	        String usernameWithUserstoreDomain = UserCoreUtil.addDomainToName(username, userStoreDomain);
	        try {
	            // start tenant flow
	            FrameworkUtils.startTenantFlow(tenantDomain);
	            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(usernameWithUserstoreDomain);

	            if (!StringUtils.isEmpty(idp) && !StringUtils.isEmpty(subject)) {
	                FederatedAssociationManager federatedAssociationManager = FrameworkUtils
	                        .getFederatedAssociationManager();
	                User user = getAssociatedUser(tenantDomain, userStoreDomain, username);
	                federatedAssociationManager.createFederatedAssociation(user, idp, subject);

	                if (log.isDebugEnabled()) {
	                    log.debug("Associated local user: " + usernameWithUserstoreDomain + " in tenant: " +
	                            tenantDomain + " to the federated subject : " + subject + " in IdP: " + idp);
	                }
	            } else {
	                throw new FrameworkException("Error while associating local user: " + usernameWithUserstoreDomain +
	                        " in tenant: " + tenantDomain + " to the federated subject : " + subject + " in IdP: " + idp);
	            }
	        } catch (FederatedAssociationManagerException e) {
	            if (isUserAlreadyAssociated(e)) {
	                log.info("An association already exists for user: " + subject + ". Skip association while JIT " +
	                        "provisioning");
	            } else {
	                throw new FrameworkException("Error while associating local user: " + usernameWithUserstoreDomain +
	                        " in tenant: " + tenantDomain + " to the federated subject : " + subject + " in IdP: " + idp, e);
	            }
	        } finally {
	            // end tenant flow
	            FrameworkUtils.endTenantFlow();
	        }
	    }

	    private User getAssociatedUser(String tenantDomain, String userStoreDomain, String username) {

	        User user = new User();
	        user.setTenantDomain(tenantDomain);
	        user.setUserStoreDomain(userStoreDomain);
	        user.setUserName(MultitenantUtils.getTenantAwareUsername(username));
	        return user;
	    }

	    private boolean isUserAlreadyAssociated(FederatedAssociationManagerException e) {

	        return e.getMessage() != null && e.getMessage().contains(FederatedAssociationConstants.ErrorMessages
	                .FEDERATED_ASSOCIATION_ALREADY_EXISTS.getDescription());
	    }

	    private void updateUserWithNewRoleSet(String username, UserStoreManager userStoreManager, List<String> rolesToAdd,
	                                          Collection<String> deletingRoles, String tenantDomain, String password) throws UserStoreException {

	        if (log.isDebugEnabled()) {
	            log.info("Deleting roles : " + Arrays.toString(deletingRoles.toArray(new String[0]))
	                    + " and Adding roles : " + Arrays.toString(rolesToAdd.toArray(new String[0])));
	        }
	        userStoreManager.updateRoleListOfUser(username, deletingRoles.toArray(new String[0]),
	                rolesToAdd.toArray(new String[0]));
	        if (log.isDebugEnabled()) {
	            log.info("Federated user: " + username + " is updated by authentication framework with roles : "
	                    + rolesToAdd);
	        }
	    }

	    private void handleFederatedUserNameEqualsToSuperAdminUserName(UserRealm realm, String username,
	                                                                   UserStoreManager userStoreManager,
	                                                                   Collection<String> deletingRoles)
	            throws UserStoreException, FrameworkException {
	        if (userStoreManager.getRealmConfiguration().isPrimary()
	                && username.equals(realm.getRealmConfiguration().getAdminUserName())) {
	            if (log.isDebugEnabled()) {
	                log.debug("Federated user's username is equal to super admin's username of local IdP.");
	            }

	            // Whether superadmin login without superadmin role is permitted
	            if (deletingRoles
	                    .contains(realm.getRealmConfiguration().getAdminRoleName())) {
	                if (log.isDebugEnabled()) {
	                    log.debug("Federated user doesn't have super admin role. Unable to sync roles, since" +
	                            " super admin role cannot be unassigned from super admin user");
	                }
	                throw new FrameworkException(
	                        "Federated user which having same username to super admin username of local IdP," +
	                                " trying login without having super admin role assigned");
	            }
	        }
	    }

	    private Map<String, String> prepareClaimMappings(Map<String, String> attributes) {
	        Map<String, String> userClaims = new HashMap<>();
	        if (attributes != null && !attributes.isEmpty()) {
	            for (Map.Entry<String, String> entry : attributes.entrySet()) {
	                String claimURI = entry.getKey();
	                String claimValue = entry.getValue();
	                if (!(StringUtils.isEmpty(claimURI) || StringUtils.isEmpty(claimValue))) {
	                    userClaims.put(claimURI, claimValue);
	                }
	            }
	        }
	        return userClaims;
	    }

	    private UserStoreManager getUserStoreManager(UserRealm realm, String userStoreDomain)
	            throws UserStoreException, FrameworkException {
	        UserStoreManager userStoreManager;
	        if (userStoreDomain != null && !userStoreDomain.isEmpty()) {
	            userStoreManager = realm.getUserStoreManager().getSecondaryUserStoreManager(
	                    userStoreDomain);
	        } else {
	            userStoreManager = realm.getUserStoreManager();
	        }

	        if (userStoreManager == null) {
	            throw new FrameworkException("Specified user store is invalid");
	        }
	        return userStoreManager;
	    }

	    /**
	     * Compute the user store which user to be provisioned
	     *
	     * @return
	     * @throws UserStoreException
	     */
	    private String getUserStoreDomain(String userStoreDomain, UserRealm realm)
	            throws FrameworkException, UserStoreException {

	        // If the any of above value is invalid, keep it empty to use primary userstore
	        if (userStoreDomain != null
	            && realm.getUserStoreManager().getSecondaryUserStoreManager(userStoreDomain) == null) {
	            throw new FrameworkException("Specified user store domain " + userStoreDomain
	                                         + " is not valid.");
	        }

	        return userStoreDomain;
	    }

	    /**
	     * Generates (random) password for user to be provisioned
	     *
	     * @return
	     */
	    protected String generatePassword() {
	        return "albana";//RandomStringUtils.randomNumeric(12);
	    }

	    /**
	     * remove user store domain from names except the domain 'Internal'
	     *
	     * @param names
	     * @return
	     */
	    private List<String> removeDomainFromNamesExcludeInternal(List<String> names, int tenantId) {
	        List<String> nameList = new ArrayList<String>();
	        for (String name : names) {
	            String userStoreDomain = IdentityUtil.extractDomainFromName(name);
	            if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userStoreDomain)) {
	                nameList.add(name);
	            } else {
	                nameList.add(UserCoreUtil.removeDomainFromName(name));
	            }
	        }
	        return nameList;
	    }

	    /**
	     * Check for internal roles and convert internal role domain names to camel case to match with predefined
	     * internal role domains.
	     *
	     * @param roles roles to verify and update
	     * @return updated role list
	     */
	    private List<String> convertInternalRoleDomainsToCamelCase(List<String> roles) {

	        List<String> updatedRoles = new ArrayList<>();

	        if (roles != null) {
	            // If internal roles exist, convert internal role domain names to case sensitive predefined domain names.
	            for (String role : roles) {
	                if (StringUtils.equalsIgnoreCase(role, UserCoreConstants.INTERNAL_DOMAIN + CarbonConstants
	                        .DOMAIN_SEPARATOR)) {
	                	log.info(UserCoreConstants.INTERNAL_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR +
	                            UserCoreUtil.removeDomainFromName(role));
	                    updatedRoles.add(UserCoreConstants.INTERNAL_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR +
	                            UserCoreUtil.removeDomainFromName(role));
	                } else if (StringUtils.equalsIgnoreCase(role, APPLICATION_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR)) {
	                    updatedRoles.add(APPLICATION_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR + UserCoreUtil
	                            .removeDomainFromName(role));
	                } else if (StringUtils.equalsIgnoreCase(role, WORKFLOW_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR)) {
	                    updatedRoles.add(WORKFLOW_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR + UserCoreUtil
	                            .removeDomainFromName(role));
	                } else {
	                    updatedRoles.add(role);
	                }
	            }
	        }

	        return updatedRoles;
	    }

	    /**
	     * Retrieve the list of roles to be deleted.
	     *
	     * @param realm            user realm
	     * @param currentRolesList current role list of the user
	     * @param rolesToAdd       roles that are about to be added
	     * @return roles to be deleted
	     * @throws UserStoreException When failed to get realm configuration
	     */
	    protected List<String> retrieveRolesToBeDeleted(UserRealm realm, List<String> currentRolesList,
	                                                    List<String> rolesToAdd) throws UserStoreException {

	        List<String> deletingRoles = new ArrayList<String>();
	        deletingRoles.addAll(currentRolesList);

	        // deletingRoles = currentRolesList - rolesToAdd
	        deletingRoles.removeAll(rolesToAdd);

	        // Exclude Internal/everyonerole from deleting role since its cannot be deleted
	        deletingRoles.remove(realm.getRealmConfiguration().getEveryOneRoleName());

	        return deletingRoles;
	    }
	    	    
	    private int provisionTenant(String subject, String tenantDomain, String password) throws FrameworkException {
	        RealmService realmService = AACAuthenticatorServiceComponent.getRealmService();
	        RegistryService registryService = AACAuthenticatorServiceComponent.getRegistryService();
	        TenantMgtAdminService tenantMgt = new TenantMgtAdminService();
	        int tenantId = -1;
	        try {
	        	tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
	            String username = MultitenantUtils.getTenantAwareUsername(subject);
	            if(tenantId == -1){        		
	            	log.info("TenantAwareUsername: " + username);
	            	TenantInfoBean tenantInfoBean = new TenantInfoBean();
    	    		tenantInfoBean.setAdmin("admin");
    	            tenantInfoBean.setFirstname("firstname");
    	            tenantInfoBean.setLastname("lastname");
    	            tenantInfoBean.setAdminPassword(password);
    	            tenantInfoBean.setTenantDomain(tenantDomain);
    	            tenantInfoBean.setEmail(username.contains("@") ? username : username+"@"+tenantDomain);
    	            tenantInfoBean.setCreatedDate(Calendar.getInstance());
    	            tenantInfoBean.setActive(true);
    	            tenantMgt.addTenant(tenantInfoBean);
    	            tenantMgt.activateTenant(tenantDomain);
    	            tenantId = tenantMgt.getTenant(tenantDomain).getTenantId();
    	            tenantInfoBean.setTenantId(tenantId);
	            }
	            log.info("tenantId: " + tenantId);
        		// activate tenant if not yet activated
        		boolean isTenantActive = realmService.getTenantManager().isTenantActive(tenantId);
        		log.info("isTenantActive : ");log.info(isTenantActive);
        		if(!isTenantActive)
        			realmService.getTenantManager().activateTenant(tenantId);
        		if(tenantDomain.equals("carbon.super"))
        			return tenantId;
        		
	            //Here when get the user realm it create admin user and group.
	            AnonymousSessionUtil.getRealmByTenantDomain(registryService, realmService, tenantDomain);//realmService.getTenantUserRealm(tenantId);	        		
        		AACAuthenticatorServiceComponent.getRegistryLoader().loadTenantRegistry(tenantId);
        		IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
//        		initializeRegistry(tenantId, tenantDomain);
        		ConfigurationContext ctx = AACAuthenticatorServiceComponent.getConfigurationContextService().getServerConfigContext();  
        		TenantAxisUtils.getTenantAxisConfiguration(tenantDomain, ctx);
        		
        		org.wso2.carbon.caching.impl.CachingAxisConfigurationObserver tenantAxisConfig = (org.wso2.carbon.caching.impl.CachingAxisConfigurationObserver) AACAuthenticatorServiceComponent.getTenantAxisConfigLoader();
        		tenantAxisConfig.terminatingConfigurationContext(ctx);
        		tenantAxisConfig.terminatedConfigurationContext(ctx);
        		tenantAxisConfig.creatingConfigurationContext(tenantId);
        		        			
        		TenantRegistryLoader tenantRegistryLoader = AACAuthenticatorServiceComponent.getRegistryLoader();
        		AACAuthenticatorServiceComponent.getIndexLoader().loadTenantIndex(tenantId);
        		tenantRegistryLoader.loadTenantRegistry(tenantId);
        		
	        } catch (Exception e) {
				throw new FrameworkException("Error during tenant creation", e);
			} 
	        return tenantId;
	    }
	    
	    public static void initializeRegistry(int tenantId, String tenantDomain) throws Exception {

	        if (tenantId != org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID) {
	            try {
	                PrivilegedCarbonContext.startTenantFlow();
	                PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
	                carbonContext.setTenantDomain(tenantDomain, true);
	                BundleContext bundleContext = AACAuthenticatorServiceComponent.getBundleContext();
	                if (bundleContext != null) {
//	                    ServiceTracker tracker = new ServiceTracker(bundleContext, AuthenticationObserver.class.getName(), null);
//	                    tracker.open();
//	                    Object[] services = tracker.getServices();
//	                    log.info("Services for authentication Observer " + services.length);
//	                    if (services != null) {
//	                        for (Object service : services) {
//	                            ((AuthenticationObserver) service).startedAuthentication(tenantId);
//	                        }
//	                    }
//	                    tracker.close();
	                    ServiceTracker tracker2 = new ServiceTracker(bundleContext, Axis2ConfigurationContextObserver.class.getName(), null);
	                    tracker2.open();
	                    Object[] services2 = tracker2.getServices();
	                    log.info("Services for tenant Observer " + services2.length);
	                    if (services2 != null) {
	                        for (Object service : services2) {
	                        	log.info(service.getClass().getName());
	                        	if(service.getClass().getName().equals("org.wso2.carbon.identity.tenant.resource.manager.TenantAwareAxis2ConfigurationContextObserver")) {
	                        		ConfigurationContext ctx = AACAuthenticatorServiceComponent.getConfigurationContextService().getServerConfigContext();
		                        	((TenantAwareAxis2ConfigurationContextObserver) service).terminatedConfigurationContext(ctx);
		                        	((TenantAwareAxis2ConfigurationContextObserver) service).terminatingConfigurationContext(ctx);
		                        	((TenantAwareAxis2ConfigurationContextObserver) service).creatingConfigurationContext(tenantId);
	                        	}
	                        }
	                    }
	                    tracker2.close();
	                    try {
	                    	AACAuthenticatorServiceComponent.getRegistryLoader().loadTenantRegistry(tenantId);
	                    } catch (Exception e) {
	                        throw new Exception("Error loading tenant registry for tenant domain " + tenantDomain, e);
	                    }
	                    try {
	                        RegistryService registryService = AACAuthenticatorServiceComponent.getRegistryService();
	                        registryService.getGovernanceSystemRegistry(tenantId);
	                    } catch (Exception e) {
	                        throw new Exception("Error obtaining governance system registry for tenant domain " +
	                                tenantDomain, e);
	                    }
	                }
	            } finally {
	                PrivilegedCarbonContext.endTenantFlow();
	            }
	        }
	    }
	    
	    private void roleProvisioning(UserStoreManager userStoreManager, String tenantDomain) throws FrameworkException{
	    	try {
	    		Permission permissionsLogin = new Permission("/permission/admin/login","ui.execute");
	        	Permission permissionsPublish = new Permission("/permission/admin/manage/api/publish","ui.execute");
	        	Permission permissionsCreate = new Permission("/permission/admin/manage/api/create","ui.execute");
	        	Permission permissionsSubscribe = new Permission("/permission/admin/manage/api/subscribe","ui.execute");
	    		
	        	Permission permissions1 = new Permission("/permission/admin/configure/governance","ui.execute");
	        	Permission permissions2 = new Permission("/_system/governance/trunk","http://www.wso2.org/projects/registry/actions/get");
	        	Permission permissions3 = new Permission("/_system/governance/trunk","http://www.wso2.org/projects/registry/actions/add");
	        	Permission permissions4 = new Permission("/_system/governance/trunk","http://www.wso2.org/projects/registry/actions/delete");
	        	Permission permissions5 = new Permission("/_system/governance/apimgt/applicationdata","http://www.wso2.org/projects/registry/actions/get");
	        	Permission permissions6 = new Permission("/_system/governance/apimgt/applicationdata","http://www.wso2.org/projects/registry/actions/add");
	        	Permission permissions7 = new Permission("/_system/governance/apimgt/applicationdata","http://www.wso2.org/projects/registry/actions/delete");
	    		Permission permissions8 = new Permission("/permission/admin/manage/resources/govern","ui.execute");
	    		Permission permissions9 = new Permission("/permission/admin/manage/resources/govern/api/add","ui.execute");
	    		Permission permissions10 = new Permission("/permission/admin/manage/resources/govern/api/list","ui.execute");
	    		Permission permissions11 = new Permission("/permission/admin/manage/resources/govern/document","ui.execute");
	    		Permission permissions12 = new Permission("/permission/admin/manage/resources/govern/generic","ui.execute");
	    		Permission permissions13 = new Permission("/permission/admin/manage/resources/govern/lifecycles","ui.execute");
	    		Permission permissions14 = new Permission("/permission/admin/manage/resources/govern/metadata","ui.execute");
	    		Permission permissions15 = new Permission("/permission/admin/manage/resources/govern/provider","ui.execute");
	    		Permission permissions16 = new Permission("/permission/admin/manage/resources/govern/reply","ui.execute");
	    		Permission permissions17 = new Permission("/permission/admin/manage/resources/govern/topic","ui.execute");
	        	boolean rolePublisherExists = userStoreManager.isExistingRole("Internal/publisher", false);
	        	boolean roleCreatorExists = userStoreManager.isExistingRole("Internal/creator", false);
	        	boolean roleSubscriberExists;
				
					roleSubscriberExists = userStoreManager.isExistingRole("Internal/subscriber", false);
				
	        	if(!rolePublisherExists)
	        		userStoreManager.addRole("Internal/publisher",new String[] {},new Permission[] {permissionsLogin, permissionsPublish},false);
	        	if(!roleSubscriberExists){
	    			log.info("creating role subscr");
	    			userStoreManager.addRole("Internal/subscriber",new String[] {}, new Permission[] {permissionsLogin,permissionsSubscribe},false);
	    		}
	        	if(!roleCreatorExists){
	    			log.info("creating role creator");
	    			userStoreManager.addRole("Internal/creator",new String[] {}, new Permission[] {permissionsLogin,permissionsCreate,permissionsPublish,permissionsSubscribe,
																	permissions1,permissions2,permissions3,permissions4,
																	permissions5,permissions6,permissions7,permissions8,
																	permissions9,permissions10,permissions11,permissions12,
																	permissions13,permissions14,permissions15,permissions16,
																	permissions17},false);
	    		}
	    	} catch (org.wso2.carbon.user.api.UserStoreException e) {
	    		throw new FrameworkException("Error during roles creation", e);
			}
	    }

}
