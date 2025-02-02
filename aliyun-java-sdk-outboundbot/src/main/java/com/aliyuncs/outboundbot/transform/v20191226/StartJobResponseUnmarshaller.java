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

package com.aliyuncs.outboundbot.transform.v20191226;

import java.util.ArrayList;
import java.util.List;

import com.aliyuncs.outboundbot.model.v20191226.StartJobResponse;
import com.aliyuncs.outboundbot.model.v20191226.StartJobResponse.KeyValuePair;
import com.aliyuncs.transform.UnmarshallerContext;


public class StartJobResponseUnmarshaller {

	public static StartJobResponse unmarshall(StartJobResponse startJobResponse, UnmarshallerContext _ctx) {
		
		startJobResponse.setRequestId(_ctx.stringValue("StartJobResponse.RequestId"));
		startJobResponse.setCode(_ctx.stringValue("StartJobResponse.Code"));
		startJobResponse.setHttpStatusCode(_ctx.integerValue("StartJobResponse.HttpStatusCode"));
		startJobResponse.setMessage(_ctx.stringValue("StartJobResponse.Message"));
		startJobResponse.setSuccess(_ctx.booleanValue("StartJobResponse.Success"));

		List<KeyValuePair> taskIds = new ArrayList<KeyValuePair>();
		for (int i = 0; i < _ctx.lengthValue("StartJobResponse.TaskIds.Length"); i++) {
			KeyValuePair keyValuePair = new KeyValuePair();
			keyValuePair.setKey(_ctx.stringValue("StartJobResponse.TaskIds["+ i +"].Key"));
			keyValuePair.setValue(_ctx.stringValue("StartJobResponse.TaskIds["+ i +"].Value"));

			taskIds.add(keyValuePair);
		}
		startJobResponse.setTaskIds(taskIds);

		List<KeyValuePair> callIds = new ArrayList<KeyValuePair>();
		for (int i = 0; i < _ctx.lengthValue("StartJobResponse.CallIds.Length"); i++) {
			KeyValuePair keyValuePair_ = new KeyValuePair();
			keyValuePair_.setKey(_ctx.stringValue("StartJobResponse.CallIds["+ i +"].Key"));
			keyValuePair_.setValue(_ctx.stringValue("StartJobResponse.CallIds["+ i +"].Value"));

			callIds.add(keyValuePair_);
		}
		startJobResponse.setCallIds(callIds);
	 
	 	return startJobResponse;
	}
}