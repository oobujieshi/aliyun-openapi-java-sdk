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

package com.aliyuncs.ons.transform.v20190214;

import com.aliyuncs.ons.model.v20190214.OnsMessageSendResponse;
import com.aliyuncs.transform.UnmarshallerContext;


public class OnsMessageSendResponseUnmarshaller {

	public static OnsMessageSendResponse unmarshall(OnsMessageSendResponse onsMessageSendResponse, UnmarshallerContext _ctx) {
		
		onsMessageSendResponse.setRequestId(_ctx.stringValue("OnsMessageSendResponse.RequestId"));
		onsMessageSendResponse.setData(_ctx.stringValue("OnsMessageSendResponse.Data"));
		onsMessageSendResponse.setHelpUrl(_ctx.stringValue("OnsMessageSendResponse.HelpUrl"));
	 
	 	return onsMessageSendResponse;
	}
}