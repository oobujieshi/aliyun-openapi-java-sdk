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

package com.aliyuncs.dataworks_public.transform.v20200518;

import com.aliyuncs.dataworks_public.model.v20200518.DeleteRemindResponse;
import com.aliyuncs.transform.UnmarshallerContext;


public class DeleteRemindResponseUnmarshaller {

	public static DeleteRemindResponse unmarshall(DeleteRemindResponse deleteRemindResponse, UnmarshallerContext _ctx) {
		
		deleteRemindResponse.setRequestId(_ctx.stringValue("DeleteRemindResponse.RequestId"));
		deleteRemindResponse.setSuccess(_ctx.booleanValue("DeleteRemindResponse.Success"));
		deleteRemindResponse.setErrorCode(_ctx.stringValue("DeleteRemindResponse.ErrorCode"));
		deleteRemindResponse.setErrorMessage(_ctx.stringValue("DeleteRemindResponse.ErrorMessage"));
		deleteRemindResponse.setHttpStatusCode(_ctx.integerValue("DeleteRemindResponse.HttpStatusCode"));
		deleteRemindResponse.setData(_ctx.booleanValue("DeleteRemindResponse.Data"));
	 
	 	return deleteRemindResponse;
	}
}