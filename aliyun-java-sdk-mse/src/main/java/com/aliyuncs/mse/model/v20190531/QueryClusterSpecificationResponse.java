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

package com.aliyuncs.mse.model.v20190531;

import java.util.List;
import com.aliyuncs.AcsResponse;
import com.aliyuncs.mse.transform.v20190531.QueryClusterSpecificationResponseUnmarshaller;
import com.aliyuncs.transform.UnmarshallerContext;

/**
 * @author auto create
 * @version 
 */
public class QueryClusterSpecificationResponse extends AcsResponse {

	private Integer httpStatusCode;

	private String requestId;

	private Boolean success;

	private String errorCode;

	private Integer code;

	private String message;

	private List<DataItem> data;

	public Integer getHttpStatusCode() {
		return this.httpStatusCode;
	}

	public void setHttpStatusCode(Integer httpStatusCode) {
		this.httpStatusCode = httpStatusCode;
	}

	public String getRequestId() {
		return this.requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public Boolean getSuccess() {
		return this.success;
	}

	public void setSuccess(Boolean success) {
		this.success = success;
	}

	public String getErrorCode() {
		return this.errorCode;
	}

	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}

	public Integer getCode() {
		return this.code;
	}

	public void setCode(Integer code) {
		this.code = code;
	}

	public String getMessage() {
		return this.message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public List<DataItem> getData() {
		return this.data;
	}

	public void setData(List<DataItem> data) {
		this.data = data;
	}

	public static class DataItem {

		private String clusterSpecificationName;

		private String diskCapacity;

		private String memoryCapacity;

		private String instanceCount;

		private String maxTps;

		private String maxCon;

		private String cpuCapacity;

		public String getClusterSpecificationName() {
			return this.clusterSpecificationName;
		}

		public void setClusterSpecificationName(String clusterSpecificationName) {
			this.clusterSpecificationName = clusterSpecificationName;
		}

		public String getDiskCapacity() {
			return this.diskCapacity;
		}

		public void setDiskCapacity(String diskCapacity) {
			this.diskCapacity = diskCapacity;
		}

		public String getMemoryCapacity() {
			return this.memoryCapacity;
		}

		public void setMemoryCapacity(String memoryCapacity) {
			this.memoryCapacity = memoryCapacity;
		}

		public String getInstanceCount() {
			return this.instanceCount;
		}

		public void setInstanceCount(String instanceCount) {
			this.instanceCount = instanceCount;
		}

		public String getMaxTps() {
			return this.maxTps;
		}

		public void setMaxTps(String maxTps) {
			this.maxTps = maxTps;
		}

		public String getMaxCon() {
			return this.maxCon;
		}

		public void setMaxCon(String maxCon) {
			this.maxCon = maxCon;
		}

		public String getCpuCapacity() {
			return this.cpuCapacity;
		}

		public void setCpuCapacity(String cpuCapacity) {
			this.cpuCapacity = cpuCapacity;
		}
	}

	@Override
	public QueryClusterSpecificationResponse getInstance(UnmarshallerContext context) {
		return	QueryClusterSpecificationResponseUnmarshaller.unmarshall(this, context);
	}

	@Override
	public boolean checkShowJsonItemName() {
		return false;
	}
}
