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

package com.aliyuncs.vs.transform.v20181212;

import java.util.ArrayList;
import java.util.List;

import com.aliyuncs.vs.model.v20181212.ListDeviceChannelsResponse;
import com.aliyuncs.vs.model.v20181212.ListDeviceChannelsResponse.Channel;
import com.aliyuncs.transform.UnmarshallerContext;


public class ListDeviceChannelsResponseUnmarshaller {

	public static ListDeviceChannelsResponse unmarshall(ListDeviceChannelsResponse listDeviceChannelsResponse, UnmarshallerContext _ctx) {
		
		listDeviceChannelsResponse.setRequestId(_ctx.stringValue("ListDeviceChannelsResponse.RequestId"));
		listDeviceChannelsResponse.setPageSize(_ctx.longValue("ListDeviceChannelsResponse.PageSize"));
		listDeviceChannelsResponse.setPageNum(_ctx.longValue("ListDeviceChannelsResponse.PageNum"));
		listDeviceChannelsResponse.setPageCount(_ctx.longValue("ListDeviceChannelsResponse.PageCount"));
		listDeviceChannelsResponse.setTotalCount(_ctx.longValue("ListDeviceChannelsResponse.TotalCount"));

		List<Channel> channels = new ArrayList<Channel>();
		for (int i = 0; i < _ctx.lengthValue("ListDeviceChannelsResponse.Channels.Length"); i++) {
			Channel channel = new Channel();
			channel.setName(_ctx.stringValue("ListDeviceChannelsResponse.Channels["+ i +"].Name"));
			channel.setDeviceId(_ctx.stringValue("ListDeviceChannelsResponse.Channels["+ i +"].DeviceId"));
			channel.setDeviceStatus(_ctx.stringValue("ListDeviceChannelsResponse.Channels["+ i +"].DeviceStatus"));
			channel.setChannelId(_ctx.longValue("ListDeviceChannelsResponse.Channels["+ i +"].ChannelId"));
			channel.setParams(_ctx.stringValue("ListDeviceChannelsResponse.Channels["+ i +"].Params"));

			channels.add(channel);
		}
		listDeviceChannelsResponse.setChannels(channels);
	 
	 	return listDeviceChannelsResponse;
	}
}