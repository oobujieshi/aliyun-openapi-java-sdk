package com.aliyuncs.kms;

public interface Constants {
    /**
     * secret type RAMCredentials
     */
    String ACCESS_KEY_SECRET_TYPE = "RAMCredentials";
    /**
     * subtype RamUserAccessKey
     */
    String RAM_USER_ACCESS_KEY_SECRET_SUB_TYPE = "RamUserAccessKey";
    /**
     * subtype TempAK
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
    /**
     * accesskey id key in secret data
     */
    String SECRET_DATA_ACCESS_KEY_ID_KEY = "AccessKeyId";
    /**
     * accesskey secret key in secret data
     */
    String SECRET_DATA_ACCESS_KEY_SECRET_KEY = "AccessKeySecret";
    /**
     * next rotation date key
     */
    String SECRET_NEXT_ROTATION_DATE_KEY = "NextRotationDate";
    
    /**
     * kms product name
     */
    String PRODUCT_NAME = "kms";

    /**
     * client key config region_id key
     */
    String CLIENT_KEY_CONFIG_REGION_ID_KEY = "region_id";
    /**
     * client key config endpoint key
     */
    String CLIENT_KEY_CONFIG_ENDPOINT_NAME_KEY = "endpoint";

    /**
     * client key config regionId key
     */
    String CLIENT_KEY_CONFIG_REGION_ID_NAME_KEY = "regionId";

    /**
     * client key config regionId key
     */
    String CLIENT_KEY_CONFIG_REGION_VPC_NAME_KEY = "vpc";

    /**
     * credentials config file name
     */
    String CREDENTIALS_PROPERTIES_CONFIG_NAME = "secretsmanager.properties";
    /**
     * client_key_password_from_env_variable key
     */
    String ENV_CLIENT_KEY_PASSWORD_FROM_ENV_VARIABLE_NAME = "client_key_password_from_env_variable";

    /**
     * client_key_password_from_file_path key
     */
    String ENV_CLIENT_KEY_PASSWORD_FROM_FILE_PATH_NAME = "client_key_password_from_file_path";

    /**
     * client key config credentials_client_key_private_key_path key
     */
    String CLIENT_KEY_CONFIG_PRIVATE_KEY_PATH_NAME_KEY = "client_key_private_key_path";
    
}

