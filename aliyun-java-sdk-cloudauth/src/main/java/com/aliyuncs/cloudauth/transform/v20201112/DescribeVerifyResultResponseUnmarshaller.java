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

package com.aliyuncs.cloudauth.transform.v20201112;

import java.util.ArrayList;
import java.util.List;

import com.aliyuncs.cloudauth.model.v20201112.DescribeVerifyResultResponse;
import com.aliyuncs.cloudauth.model.v20201112.DescribeVerifyResultResponse.ResultObject;
import com.aliyuncs.cloudauth.model.v20201112.DescribeVerifyResultResponse.ResultObject.Material;
import com.aliyuncs.cloudauth.model.v20201112.DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo;
import com.aliyuncs.transform.UnmarshallerContext;


public class DescribeVerifyResultResponseUnmarshaller {

	public static DescribeVerifyResultResponse unmarshall(DescribeVerifyResultResponse describeVerifyResultResponse, UnmarshallerContext _ctx) {
		
		describeVerifyResultResponse.setRequestId(_ctx.stringValue("DescribeVerifyResultResponse.RequestId"));
		describeVerifyResultResponse.setCode(_ctx.stringValue("DescribeVerifyResultResponse.Code"));
		describeVerifyResultResponse.setMessage(_ctx.stringValue("DescribeVerifyResultResponse.Message"));
		describeVerifyResultResponse.setSuccess(_ctx.booleanValue("DescribeVerifyResultResponse.Success"));

		ResultObject resultObject = new ResultObject();
		resultObject.setVerifyStatus(_ctx.integerValue("DescribeVerifyResultResponse.ResultObject.VerifyStatus"));
		resultObject.setAuthorityComparisionScore(_ctx.floatValue("DescribeVerifyResultResponse.ResultObject.AuthorityComparisionScore"));
		resultObject.setFaceComparisonScore(_ctx.floatValue("DescribeVerifyResultResponse.ResultObject.FaceComparisonScore"));
		resultObject.setIdCardFaceComparisonScore(_ctx.floatValue("DescribeVerifyResultResponse.ResultObject.IdCardFaceComparisonScore"));

		Material material = new Material();
		material.setFaceImageUrl(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.FaceImageUrl"));
		material.setIdCardName(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardName"));
		material.setIdCardNumber(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardNumber"));
		material.setFaceQuality(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.FaceQuality"));
		material.setFaceGlobalUrl(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.FaceGlobalUrl"));
		material.setFaceMask(_ctx.booleanValue("DescribeVerifyResultResponse.ResultObject.Material.FaceMask"));

		List<String> videoUrls = new ArrayList<String>();
		for (int i = 0; i < _ctx.lengthValue("DescribeVerifyResultResponse.ResultObject.Material.VideoUrls.Length"); i++) {
			videoUrls.add(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.VideoUrls["+ i +"]"));
		}
		material.setVideoUrls(videoUrls);

		IdCardInfo idCardInfo = new IdCardInfo();
		idCardInfo.setNumber(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.Number"));
		idCardInfo.setAddress(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.Address"));
		idCardInfo.setNationality(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.Nationality"));
		idCardInfo.setEndDate(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.EndDate"));
		idCardInfo.setFrontImageUrl(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.FrontImageUrl"));
		idCardInfo.setAuthority(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.Authority"));
		idCardInfo.setSex(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.Sex"));
		idCardInfo.setName(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.Name"));
		idCardInfo.setBirth(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.Birth"));
		idCardInfo.setBackImageUrl(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.BackImageUrl"));
		idCardInfo.setStartDate(_ctx.stringValue("DescribeVerifyResultResponse.ResultObject.Material.IdCardInfo.StartDate"));
		material.setIdCardInfo(idCardInfo);
		resultObject.setMaterial(material);
		describeVerifyResultResponse.setResultObject(resultObject);
	 
	 	return describeVerifyResultResponse;
	}
}