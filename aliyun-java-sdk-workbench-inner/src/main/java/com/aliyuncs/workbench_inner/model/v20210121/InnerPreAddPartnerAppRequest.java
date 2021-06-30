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

package com.aliyuncs.workbench_inner.model.v20210121;

import com.aliyuncs.RpcAcsRequest;
import com.aliyuncs.http.MethodType;

/**
 * @author auto create
 * @version 
 */
public class InnerPreAddPartnerAppRequest extends RpcAcsRequest<InnerPreAddPartnerAppResponse> {
	   

	private String partnerAppInfo;

	private String currentOrgId;

	private String source;

	private String userId;
	public InnerPreAddPartnerAppRequest() {
		super("Workbench-inner", "2021-01-21", "InnerPreAddPartnerApp");
		setMethod(MethodType.POST);
	}

	public String getPartnerAppInfo() {
		return this.partnerAppInfo;
	}

	public void setPartnerAppInfo(String partnerAppInfo) {
		this.partnerAppInfo = partnerAppInfo;
		if(partnerAppInfo != null){
			putQueryParameter("PartnerAppInfo", partnerAppInfo);
		}
	}

	public String getCurrentOrgId() {
		return this.currentOrgId;
	}

	public void setCurrentOrgId(String currentOrgId) {
		this.currentOrgId = currentOrgId;
		if(currentOrgId != null){
			putQueryParameter("CurrentOrgId", currentOrgId);
		}
	}

	public String getSource() {
		return this.source;
	}

	public void setSource(String source) {
		this.source = source;
		if(source != null){
			putQueryParameter("Source", source);
		}
	}

	public String getUserId() {
		return this.userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
		if(userId != null){
			putQueryParameter("UserId", userId);
		}
	}

	@Override
	public Class<InnerPreAddPartnerAppResponse> getResponseClass() {
		return InnerPreAddPartnerAppResponse.class;
	}

}
