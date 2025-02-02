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
import com.aliyuncs.mse.transform.v20190531.ListAlarmHistoriesResponseUnmarshaller;
import com.aliyuncs.transform.UnmarshallerContext;

/**
 * @author auto create
 * @version 
 */
public class ListAlarmHistoriesResponse extends AcsResponse {

	private String httpCode;

	private Integer totalCount;

	private String requestId;

	private String message;

	private Integer pageSize;

	private Integer pageNumber;

	private String errorCode;

	private Boolean success;

	private List<AlarmHistoryModel> data;

	public String getHttpCode() {
		return this.httpCode;
	}

	public void setHttpCode(String httpCode) {
		this.httpCode = httpCode;
	}

	public Integer getTotalCount() {
		return this.totalCount;
	}

	public void setTotalCount(Integer totalCount) {
		this.totalCount = totalCount;
	}

	public String getRequestId() {
		return this.requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public String getMessage() {
		return this.message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public Integer getPageSize() {
		return this.pageSize;
	}

	public void setPageSize(Integer pageSize) {
		this.pageSize = pageSize;
	}

	public Integer getPageNumber() {
		return this.pageNumber;
	}

	public void setPageNumber(Integer pageNumber) {
		this.pageNumber = pageNumber;
	}

	public String getErrorCode() {
		return this.errorCode;
	}

	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}

	public Boolean getSuccess() {
		return this.success;
	}

	public void setSuccess(Boolean success) {
		this.success = success;
	}

	public List<AlarmHistoryModel> getData() {
		return this.data;
	}

	public void setData(List<AlarmHistoryModel> data) {
		this.data = data;
	}

	public static class AlarmHistoryModel {

		private String alarmTime;

		private String alarmEmail;

		private String alarmDingDing;

		private String alarmPhone;

		private String alarmName;

		private String alarmContent;

		public String getAlarmTime() {
			return this.alarmTime;
		}

		public void setAlarmTime(String alarmTime) {
			this.alarmTime = alarmTime;
		}

		public String getAlarmEmail() {
			return this.alarmEmail;
		}

		public void setAlarmEmail(String alarmEmail) {
			this.alarmEmail = alarmEmail;
		}

		public String getAlarmDingDing() {
			return this.alarmDingDing;
		}

		public void setAlarmDingDing(String alarmDingDing) {
			this.alarmDingDing = alarmDingDing;
		}

		public String getAlarmPhone() {
			return this.alarmPhone;
		}

		public void setAlarmPhone(String alarmPhone) {
			this.alarmPhone = alarmPhone;
		}

		public String getAlarmName() {
			return this.alarmName;
		}

		public void setAlarmName(String alarmName) {
			this.alarmName = alarmName;
		}

		public String getAlarmContent() {
			return this.alarmContent;
		}

		public void setAlarmContent(String alarmContent) {
			this.alarmContent = alarmContent;
		}
	}

	@Override
	public ListAlarmHistoriesResponse getInstance(UnmarshallerContext context) {
		return	ListAlarmHistoriesResponseUnmarshaller.unmarshall(this, context);
	}

	@Override
	public boolean checkShowJsonItemName() {
		return false;
	}
}
