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

package com.aliyuncs.cloudauth.transform.v20200618;

import com.aliyuncs.cloudauth.model.v20200618.SendSmsResponse;
import com.aliyuncs.cloudauth.model.v20200618.SendSmsResponse.ResultObject;
import com.aliyuncs.transform.UnmarshallerContext;


public class SendSmsResponseUnmarshaller {

	public static SendSmsResponse unmarshall(SendSmsResponse sendSmsResponse, UnmarshallerContext _ctx) {
		
		sendSmsResponse.setRequestId(_ctx.stringValue("SendSmsResponse.RequestId"));
		sendSmsResponse.setMessage(_ctx.stringValue("SendSmsResponse.Message"));
		sendSmsResponse.setCode(_ctx.stringValue("SendSmsResponse.Code"));

		ResultObject resultObject = new ResultObject();
		resultObject.setBizId(_ctx.stringValue("SendSmsResponse.ResultObject.BizId"));
		sendSmsResponse.setResultObject(resultObject);
	 
	 	return sendSmsResponse;
	}
}