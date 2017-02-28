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

package it.smartcommunitylab.aac.wso2.model;

import java.util.List;

/**
 * @author raman
 *
 */
public class RoleModel {

	List<String> addRoles, removeRoles;
	public List<String> getAddRoles() {
		return addRoles;
	}
	public void setAddRoles(List<String> addRoles) {
		this.addRoles = addRoles;
	}
	public List<String> getRemoveRoles() {
		return removeRoles;
	}
	public void setRemoveRoles(List<String> removeRoles) {
		this.removeRoles = removeRoles;
	}
	
}
