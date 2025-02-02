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

package com.aliyuncs.oos.model.v20190601;

import java.util.List;
import java.util.Map;
import com.aliyuncs.AcsResponse;
import com.aliyuncs.oos.transform.v20190601.ListExecutionsResponseUnmarshaller;
import com.aliyuncs.transform.UnmarshallerContext;

/**
 * @author auto create
 * @version 
 */
public class ListExecutionsResponse extends AcsResponse {

	private String requestId;

	private Integer maxResults;

	private String nextToken;

	private List<Execution> executions;

	public String getRequestId() {
		return this.requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public Integer getMaxResults() {
		return this.maxResults;
	}

	public void setMaxResults(Integer maxResults) {
		this.maxResults = maxResults;
	}

	public String getNextToken() {
		return this.nextToken;
	}

	public void setNextToken(String nextToken) {
		this.nextToken = nextToken;
	}

	public List<Execution> getExecutions() {
		return this.executions;
	}

	public void setExecutions(List<Execution> executions) {
		this.executions = executions;
	}

	public static class Execution {

		private String executionId;

		private String templateName;

		private String templateId;

		private String templateVersion;

		private String mode;

		private String executedBy;

		private String startDate;

		private String endDate;

		private String createDate;

		private String updateDate;

		private String status;

		private String statusMessage;

		private String statusReason;

		private String waitingStatus;

		private String parentExecutionId;

		private Map<Object,Object> parameters;

		private String outputs;

		private String safetyCheck;

		private Boolean isParent;

		private String ramRole;

		private Map<Object,Object> counters;

		private String category;

		private Map<Object,Object> tags;

		private String description;

		private String targets;

		private String lastTriggerTime;

		private String lastTriggerStatus;

		private String lastSuccessfulTriggerTime;

		private String resourceStatus;

		private String resourceGroupId;

		private List<CurrentTask> currentTasks;

		public String getExecutionId() {
			return this.executionId;
		}

		public void setExecutionId(String executionId) {
			this.executionId = executionId;
		}

		public String getTemplateName() {
			return this.templateName;
		}

		public void setTemplateName(String templateName) {
			this.templateName = templateName;
		}

		public String getTemplateId() {
			return this.templateId;
		}

		public void setTemplateId(String templateId) {
			this.templateId = templateId;
		}

		public String getTemplateVersion() {
			return this.templateVersion;
		}

		public void setTemplateVersion(String templateVersion) {
			this.templateVersion = templateVersion;
		}

		public String getMode() {
			return this.mode;
		}

		public void setMode(String mode) {
			this.mode = mode;
		}

		public String getExecutedBy() {
			return this.executedBy;
		}

		public void setExecutedBy(String executedBy) {
			this.executedBy = executedBy;
		}

		public String getStartDate() {
			return this.startDate;
		}

		public void setStartDate(String startDate) {
			this.startDate = startDate;
		}

		public String getEndDate() {
			return this.endDate;
		}

		public void setEndDate(String endDate) {
			this.endDate = endDate;
		}

		public String getCreateDate() {
			return this.createDate;
		}

		public void setCreateDate(String createDate) {
			this.createDate = createDate;
		}

		public String getUpdateDate() {
			return this.updateDate;
		}

		public void setUpdateDate(String updateDate) {
			this.updateDate = updateDate;
		}

		public String getStatus() {
			return this.status;
		}

		public void setStatus(String status) {
			this.status = status;
		}

		public String getStatusMessage() {
			return this.statusMessage;
		}

		public void setStatusMessage(String statusMessage) {
			this.statusMessage = statusMessage;
		}

		public String getStatusReason() {
			return this.statusReason;
		}

		public void setStatusReason(String statusReason) {
			this.statusReason = statusReason;
		}

		public String getWaitingStatus() {
			return this.waitingStatus;
		}

		public void setWaitingStatus(String waitingStatus) {
			this.waitingStatus = waitingStatus;
		}

		public String getParentExecutionId() {
			return this.parentExecutionId;
		}

		public void setParentExecutionId(String parentExecutionId) {
			this.parentExecutionId = parentExecutionId;
		}

		public Map<Object,Object> getParameters() {
			return this.parameters;
		}

		public void setParameters(Map<Object,Object> parameters) {
			this.parameters = parameters;
		}

		public String getOutputs() {
			return this.outputs;
		}

		public void setOutputs(String outputs) {
			this.outputs = outputs;
		}

		public String getSafetyCheck() {
			return this.safetyCheck;
		}

		public void setSafetyCheck(String safetyCheck) {
			this.safetyCheck = safetyCheck;
		}

		public Boolean getIsParent() {
			return this.isParent;
		}

		public void setIsParent(Boolean isParent) {
			this.isParent = isParent;
		}

		public String getRamRole() {
			return this.ramRole;
		}

		public void setRamRole(String ramRole) {
			this.ramRole = ramRole;
		}

		public Map<Object,Object> getCounters() {
			return this.counters;
		}

		public void setCounters(Map<Object,Object> counters) {
			this.counters = counters;
		}

		public String getCategory() {
			return this.category;
		}

		public void setCategory(String category) {
			this.category = category;
		}

		public Map<Object,Object> getTags() {
			return this.tags;
		}

		public void setTags(Map<Object,Object> tags) {
			this.tags = tags;
		}

		public String getDescription() {
			return this.description;
		}

		public void setDescription(String description) {
			this.description = description;
		}

		public String getTargets() {
			return this.targets;
		}

		public void setTargets(String targets) {
			this.targets = targets;
		}

		public String getLastTriggerTime() {
			return this.lastTriggerTime;
		}

		public void setLastTriggerTime(String lastTriggerTime) {
			this.lastTriggerTime = lastTriggerTime;
		}

		public String getLastTriggerStatus() {
			return this.lastTriggerStatus;
		}

		public void setLastTriggerStatus(String lastTriggerStatus) {
			this.lastTriggerStatus = lastTriggerStatus;
		}

		public String getLastSuccessfulTriggerTime() {
			return this.lastSuccessfulTriggerTime;
		}

		public void setLastSuccessfulTriggerTime(String lastSuccessfulTriggerTime) {
			this.lastSuccessfulTriggerTime = lastSuccessfulTriggerTime;
		}

		public String getResourceStatus() {
			return this.resourceStatus;
		}

		public void setResourceStatus(String resourceStatus) {
			this.resourceStatus = resourceStatus;
		}

		public String getResourceGroupId() {
			return this.resourceGroupId;
		}

		public void setResourceGroupId(String resourceGroupId) {
			this.resourceGroupId = resourceGroupId;
		}

		public List<CurrentTask> getCurrentTasks() {
			return this.currentTasks;
		}

		public void setCurrentTasks(List<CurrentTask> currentTasks) {
			this.currentTasks = currentTasks;
		}

		public static class CurrentTask {

			private String taskExecutionId;

			private String taskName;

			private String taskAction;

			public String getTaskExecutionId() {
				return this.taskExecutionId;
			}

			public void setTaskExecutionId(String taskExecutionId) {
				this.taskExecutionId = taskExecutionId;
			}

			public String getTaskName() {
				return this.taskName;
			}

			public void setTaskName(String taskName) {
				this.taskName = taskName;
			}

			public String getTaskAction() {
				return this.taskAction;
			}

			public void setTaskAction(String taskAction) {
				this.taskAction = taskAction;
			}
		}
	}

	@Override
	public ListExecutionsResponse getInstance(UnmarshallerContext context) {
		return	ListExecutionsResponseUnmarshaller.unmarshall(this, context);
	}

	@Override
	public boolean checkShowJsonItemName() {
		return false;
	}
}
