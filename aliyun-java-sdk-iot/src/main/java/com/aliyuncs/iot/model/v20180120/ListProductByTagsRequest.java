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

package com.aliyuncs.iot.model.v20180120;

import com.aliyuncs.RpcAcsRequest;
import java.util.List;

/**
 * @author auto create
 * @version 
 */
public class ListProductByTagsRequest extends RpcAcsRequest<ListProductByTagsResponse> {
	
	public ListProductByTagsRequest() {
		super("Iot", "2018-01-20", "ListProductByTags");
	}

	private List<ProductTag> productTags;

	private Integer pageSize;

	private Integer currentPage;

	public List<ProductTag> getProductTags() {
		return this.productTags;
	}

	public void setProductTags(List<ProductTag> productTags) {
		this.productTags = productTags;	
		if (productTags != null) {
			for (int depth1 = 0; depth1 < productTags.size(); depth1++) {
				putQueryParameter("ProductTag." + (depth1 + 1) + ".TagValue" , productTags.get(depth1).getTagValue());
				putQueryParameter("ProductTag." + (depth1 + 1) + ".TagKey" , productTags.get(depth1).getTagKey());
			}
		}	
	}

	public Integer getPageSize() {
		return this.pageSize;
	}

	public void setPageSize(Integer pageSize) {
		this.pageSize = pageSize;
		if(pageSize != null){
			putQueryParameter("PageSize", pageSize.toString());
		}
	}

	public Integer getCurrentPage() {
		return this.currentPage;
	}

	public void setCurrentPage(Integer currentPage) {
		this.currentPage = currentPage;
		if(currentPage != null){
			putQueryParameter("CurrentPage", currentPage.toString());
		}
	}

	public static class ProductTag {

		private String tagValue;

		private String tagKey;

		public String getTagValue() {
			return this.tagValue;
		}

		public void setTagValue(String tagValue) {
			this.tagValue = tagValue;
		}

		public String getTagKey() {
			return this.tagKey;
		}

		public void setTagKey(String tagKey) {
			this.tagKey = tagKey;
		}
	}

	@Override
	public Class<ListProductByTagsResponse> getResponseClass() {
		return ListProductByTagsResponse.class;
	}

}
