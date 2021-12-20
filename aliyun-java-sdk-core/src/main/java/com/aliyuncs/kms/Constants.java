package com.aliyuncs.kms;

public interface Constants {
    /**
     * access key secret type
     */
    String ACCESS_KEY_SECRET_TYPE = "RAMCredentials";

    /**
     * RamUserAccessKey subtype
     */
    String RAM_USER_ACCESS_KEY_SECRET_SUB_TYPE = "RamUserAccessKey";
    /**
     * TempAK subtype
     */
    String TEMP_AK_SECRET_SUB_TYPE = "TempAK";

    /**
     * STS subtype
     */
    String STS_SECRET_SUB_TYPE = "STS";
    /**
     * extended config secret subtype key
     */
    String EXTENDED_CONFIG_PROPERTY_SECRET_SUB_TYPE_KEY = "SecretSubType";

    String SECRET_DATA_ACCESS_KEY_ID_KEY = "AccessKeyId";

    String SECRET_DATA_ACCESS_KEY_SECRET_KEY = "AccessKeySecret";

    String SECRET_NEXT_ROTATION_DATE_KEY = "NextRotationDate";

}
