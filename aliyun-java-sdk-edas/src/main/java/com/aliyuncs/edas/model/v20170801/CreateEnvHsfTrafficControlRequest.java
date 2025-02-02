/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aliyuncs.edas.model.v20170801;

import com.aliyuncs.RoaAcsRequest;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.edas.Endpoint;

/**
 * @author auto create
 * @version 
 */
public class CreateEnvHsfTrafficControlRequest extends RoaAcsRequest<CreateEnvHsfTrafficControlResponse> {
	   

	private String paramTypes;

	private String condition;

	private String appId;

	private String labelAdviceName;

	private String pointcutName;

	private String serviceName;

	private String triggerPolicy;

	private String group;

	private String methodName;
	public CreateEnvHsfTrafficControlRequest() {
		super("Edas", "2017-08-01", "CreateEnvHsfTrafficControl", "edas");
		setUriPattern("/pop/v5/gray/env_hsf_traffic_control");
		setMethod(MethodType.POST);
		try {
			com.aliyuncs.AcsRequest.class.getDeclaredField("productEndpointMap").set(this, Endpoint.endpointMap);
			com.aliyuncs.AcsRequest.class.getDeclaredField("productEndpointRegional").set(this, Endpoint.endpointRegionalType);
		} catch (Exception e) {}
	}

	public String getParamTypes() {
		return this.paramTypes;
	}

	public void setParamTypes(String paramTypes) {
		this.paramTypes = paramTypes;
		if(paramTypes != null){
			putBodyParameter("ParamTypes", paramTypes);
		}
	}

	public String getCondition() {
		return this.condition;
	}

	public void setCondition(String condition) {
		this.condition = condition;
		if(condition != null){
			putBodyParameter("Condition", condition);
		}
	}

	public String getAppId() {
		return this.appId;
	}

	public void setAppId(String appId) {
		this.appId = appId;
		if(appId != null){
			putBodyParameter("AppId", appId);
		}
	}

	public String getLabelAdviceName() {
		return this.labelAdviceName;
	}

	public void setLabelAdviceName(String labelAdviceName) {
		this.labelAdviceName = labelAdviceName;
		if(labelAdviceName != null){
			putBodyParameter("LabelAdviceName", labelAdviceName);
		}
	}

	public String getPointcutName() {
		return this.pointcutName;
	}

	public void setPointcutName(String pointcutName) {
		this.pointcutName = pointcutName;
		if(pointcutName != null){
			putBodyParameter("PointcutName", pointcutName);
		}
	}

	public String getServiceName() {
		return this.serviceName;
	}

	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
		if(serviceName != null){
			putBodyParameter("ServiceName", serviceName);
		}
	}

	public String getTriggerPolicy() {
		return this.triggerPolicy;
	}

	public void setTriggerPolicy(String triggerPolicy) {
		this.triggerPolicy = triggerPolicy;
		if(triggerPolicy != null){
			putBodyParameter("TriggerPolicy", triggerPolicy);
		}
	}

	public String getGroup() {
		return this.group;
	}

	public void setGroup(String group) {
		this.group = group;
		if(group != null){
			putBodyParameter("Group", group);
		}
	}

	public String getMethodName() {
		return this.methodName;
	}

	public void setMethodName(String methodName) {
		this.methodName = methodName;
		if(methodName != null){
			putBodyParameter("MethodName", methodName);
		}
	}

	@Override
	public Class<CreateEnvHsfTrafficControlResponse> getResponseClass() {
		return CreateEnvHsfTrafficControlResponse.class;
	}

}
