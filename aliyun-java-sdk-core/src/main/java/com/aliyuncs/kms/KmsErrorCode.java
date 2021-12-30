package com.aliyuncs.kms;

public interface KmsErrorCode {
    /**
     * KMS Server socket connect time out error code
     */
    String SDK_READ_TIMEOUT = "SDK.ReadTimeout";

    /**
     * KMS Server unreachable error code
     */
    String SDK_SERVER_UNREACHABLE = "SDK.ServerUnreachable";

    /**
     * KMS Server throttling error code
     */
    String REJECTED_THROTTLING = "Rejected.Throttling";

    /**
     * KMS Server service unavailable temporary error code
     */
    String SERVICE_UNAVAILABLE_TEMPORARY = "ServiceUnavailableTemporary";

    /**
     * KMS Server internal failure error code
     */
    String INTERNAL_FAILURE = "InternalFailure";
}
