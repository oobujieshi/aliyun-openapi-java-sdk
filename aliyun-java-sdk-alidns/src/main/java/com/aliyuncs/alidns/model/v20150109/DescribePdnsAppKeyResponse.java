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

package com.aliyuncs.alidns.model.v20150109;

import com.aliyuncs.AcsResponse;
import com.aliyuncs.alidns.transform.v20150109.DescribePdnsAppKeyResponseUnmarshaller;
import com.aliyuncs.transform.UnmarshallerContext;

/**
 * @author auto create
 * @version 
 */
public class DescribePdnsAppKeyResponse extends AcsResponse {

	private String requestId;

	private AppKey appKey;

	public String getRequestId() {
		return this.requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public AppKey getAppKey() {
		return this.appKey;
	}

	public void setAppKey(AppKey appKey) {
		this.appKey = appKey;
	}

	public static class AppKey {

		private String state;

		private String appKeyId;

		private String createDate;

		private String appKeySecret;

		public String getState() {
			return this.state;
		}

		public void setState(String state) {
			this.state = state;
		}

		public String getAppKeyId() {
			return this.appKeyId;
		}

		public void setAppKeyId(String appKeyId) {
			this.appKeyId = appKeyId;
		}

		public String getCreateDate() {
			return this.createDate;
		}

		public void setCreateDate(String createDate) {
			this.createDate = createDate;
		}

		public String getAppKeySecret() {
			return this.appKeySecret;
		}

		public void setAppKeySecret(String appKeySecret) {
			this.appKeySecret = appKeySecret;
		}
	}

	@Override
	public DescribePdnsAppKeyResponse getInstance(UnmarshallerContext context) {
		return	DescribePdnsAppKeyResponseUnmarshaller.unmarshall(this, context);
	}

	@Override
	public boolean checkShowJsonItemName() {
		return false;
	}
}
