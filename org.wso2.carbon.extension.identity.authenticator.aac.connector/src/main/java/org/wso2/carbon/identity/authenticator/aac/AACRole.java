package org.wso2.carbon.identity.authenticator.aac;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AACRole {
	
	private int id;
	private String scope;
	private String role;
	private String context;
	private String space;
	private String authority;
	private static final String PROVIDER = "ROLE_PROVIDER";
	private static final String USER = "ROLE_USER";
	public enum RoleScope {
		SYSTEM, APPLICATION, TENANT, USER
	}
	
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}
	public String getSpace() {
		return space;
	}
	public void setSpace(String space) {
		this.space = space;
	}
	public String getContext() {
		return context;
	}
	public void setContext(String context) {
		this.context = context;
	}
	public String getAuthority() {
		return authority;
	}
	public void setAuthority(String authority) {
		this.authority = authority;
	}
	
}
