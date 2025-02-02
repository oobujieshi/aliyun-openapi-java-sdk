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

package com.aliyuncs.cloudauth.model.v20190307;

import com.aliyuncs.AcsResponse;
import com.aliyuncs.cloudauth.transform.v20190307.InitDeviceResponseUnmarshaller;
import com.aliyuncs.transform.UnmarshallerContext;

/**
 * @author auto create
 * @version 
 */
public class InitDeviceResponse extends AcsResponse {

	private String code;

	private String message;

	private String requestId;

	private ResultObject resultObject;

	public String getCode() {
		return this.code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getMessage() {
		return this.message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getRequestId() {
		return this.requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public ResultObject getResultObject() {
		return this.resultObject;
	}

	public void setResultObject(ResultObject resultObject) {
		this.resultObject = resultObject;
	}

	public static class ResultObject {

		private String ossEndPoint;

		private String retCodeSub;

		private String protocol;

		private String certifyId;

		private String extParams;

		private String message;

		private String fileName;

		private String accessKeyId;

		private String presignedUrl;

		private String securityToken;

		private String fileNamePrefix;

		private String bucketName;

		private String accessKeySecret;

		private String retMessageSub;

		private String retCode;

		public String getOssEndPoint() {
			return this.ossEndPoint;
		}

		public void setOssEndPoint(String ossEndPoint) {
			this.ossEndPoint = ossEndPoint;
		}

		public String getRetCodeSub() {
			return this.retCodeSub;
		}

		public void setRetCodeSub(String retCodeSub) {
			this.retCodeSub = retCodeSub;
		}

		public String getBizProtocol() {
			return this.protocol;
		}

		public void setBizProtocol(String protocol) {
			this.protocol = protocol;
		}

		public String getCertifyId() {
			return this.certifyId;
		}

		public void setCertifyId(String certifyId) {
			this.certifyId = certifyId;
		}

		public String getExtParams() {
			return this.extParams;
		}

		public void setExtParams(String extParams) {
			this.extParams = extParams;
		}

		public String getMessage() {
			return this.message;
		}

		public void setMessage(String message) {
			this.message = message;
		}

		public String getFileName() {
			return this.fileName;
		}

		public void setFileName(String fileName) {
			this.fileName = fileName;
		}

		public String getAccessKeyId() {
			return this.accessKeyId;
		}

		public void setAccessKeyId(String accessKeyId) {
			this.accessKeyId = accessKeyId;
		}

		public String getPresignedUrl() {
			return this.presignedUrl;
		}

		public void setPresignedUrl(String presignedUrl) {
			this.presignedUrl = presignedUrl;
		}

		public String getSecurityToken() {
			return this.securityToken;
		}

		public void setSecurityToken(String securityToken) {
			this.securityToken = securityToken;
		}

		public String getFileNamePrefix() {
			return this.fileNamePrefix;
		}

		public void setFileNamePrefix(String fileNamePrefix) {
			this.fileNamePrefix = fileNamePrefix;
		}

		public String getBucketName() {
			return this.bucketName;
		}

		public void setBucketName(String bucketName) {
			this.bucketName = bucketName;
		}

		public String getAccessKeySecret() {
			return this.accessKeySecret;
		}

		public void setAccessKeySecret(String accessKeySecret) {
			this.accessKeySecret = accessKeySecret;
		}

		public String getRetMessageSub() {
			return this.retMessageSub;
		}

		public void setRetMessageSub(String retMessageSub) {
			this.retMessageSub = retMessageSub;
		}

		public String getRetCode() {
			return this.retCode;
		}

		public void setRetCode(String retCode) {
			this.retCode = retCode;
		}
	}

	@Override
	public InitDeviceResponse getInstance(UnmarshallerContext context) {
		return	InitDeviceResponseUnmarshaller.unmarshall(this, context);
	}

	@Override
	public boolean checkShowJsonItemName() {
		return false;
	}
}
