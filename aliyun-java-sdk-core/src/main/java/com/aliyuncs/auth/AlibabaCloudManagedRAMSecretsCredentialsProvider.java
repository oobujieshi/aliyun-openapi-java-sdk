package com.aliyuncs.auth;


import com.aliyuncs.IAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.exceptions.ServerException;
import com.aliyuncs.kms.Constants;
import com.aliyuncs.kms.model.v20160120.GetSecretValueRequest;
import com.aliyuncs.kms.model.v20160120.GetSecretValueResponse;
import com.aliyuncs.utils.ClientKeyUtils;
import com.aliyuncs.utils.DateUtils;
import com.aliyuncs.utils.StringUtils;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.util.Map;

public class AlibabaCloudManagedRAMSecretsCredentialsProvider implements AlibabaCloudCredentialsProvider {

    public static final int DEFAULT_DURATION_SECONDS = 3600;
    public static final String STAGE_ACS_CURRENT = "ACSCurrent";
    private long sessionDurationSeconds = DEFAULT_DURATION_SECONDS;
    private BasicSessionCredentials sessionCredentials = null;
    private String secretName;
    private IAcsClient kmsClient;
    private Gson gson = new Gson();

    public AlibabaCloudManagedRAMSecretsCredentialsProvider(String secretName) {
        if (StringUtils.isEmpty(secretName)) {
            throw new IllegalArgumentException("the param[secretName] is required");
        }
        kmsClient = ClientKeyUtils.getAcsClientByClientKey("");
        this.secretName = secretName;
    }

    public AlibabaCloudManagedRAMSecretsCredentialsProvider(String filePath, String secretName) {
        if (StringUtils.isEmpty(secretName)) {
            throw new IllegalArgumentException("the param[secretName] is required");
        }
        kmsClient = ClientKeyUtils.getAcsClientByClientKey(filePath);
        this.secretName = secretName;
    }


    public AlibabaCloudManagedRAMSecretsCredentialsProvider withDurationSeconds(long seconds) {
        this.sessionDurationSeconds = seconds;
        return this;
    }

    public AlibabaCloudManagedRAMSecretsCredentialsProvider withKmsClient(IAcsClient client) {
        this.kmsClient = client;
        return this;
    }

    @Override
    public AlibabaCloudCredentials getCredentials() throws ClientException, ServerException {
        if (sessionCredentials == null || sessionCredentials.willSoonExpire()) {
            sessionCredentials = getNewSessionCredentials();
        }
        return sessionCredentials;
    }

    private BasicSessionCredentials getNewSessionCredentials() throws ClientException, ServerException {
        GetSecretValueRequest request = new GetSecretValueRequest();
        request.setVersionStage(STAGE_ACS_CURRENT);
        request.setFetchExtendedConfig(true);
        request.setSecretName(secretName);
        GetSecretValueResponse response = this.kmsClient.getAcsResponse(request);
        return resolveResponse(response);
    }

    private BasicSessionCredentials resolveResponse(GetSecretValueResponse response) {
        String secretType = response.getSecretType();
        if (Constants.ACCESS_KEY_SECRET_TYPE.equalsIgnoreCase(secretType)) {
            String secretData = response.getSecretData();
            if (StringUtils.isEmpty(secretData)) {
                throw new RuntimeException("the secret data is empty");
            }
            String extendedConfig = response.getExtendedConfig();
            if (extendedConfig != null) {
                Map<String, String> map;
                Map<String, String> secretDataMap;
                try {
                    secretDataMap = gson.fromJson(secretData, Map.class);
                    map = gson.fromJson(extendedConfig, Map.class);
                } catch (JsonSyntaxException jsonSyntaxException) {
                    throw new RuntimeException(jsonSyntaxException);
                }
                String secretSubType = map.getOrDefault(Constants.EXTENDED_CONFIG_PROPERTY_SECRET_SUB_TYPE_KEY, "");
                String nextRotationDate = map.getOrDefault(Constants.SECRET_NEXT_ROTATION_DATE_KEY, "");
                if (StringUtils.isEmpty(nextRotationDate)) {
                    throw new RuntimeException("the next rotation date is empty");
                }
                long nextRotationTime = DateUtils.parseDate(nextRotationDate, DateUtils.TIMEZONE_DATE_PATTERN);
                long nextRotationDurationSeconds = nextRotationTime - System.currentTimeMillis() / 1000;
                if ((nextRotationTime - System.currentTimeMillis()) < sessionDurationSeconds) {
                    sessionDurationSeconds = nextRotationDurationSeconds;
                }
                switch (secretSubType) {
                    case Constants.RAM_USER_ACCESS_KEY_SECRET_SUB_TYPE:
                        String accessKeyId = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_ID_KEY, "");
                        String accessKeySecret = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_SECRET_KEY, "");
                        return new BasicSessionCredentials(
                                accessKeyId,
                                accessKeySecret,
                                null,
                                sessionDurationSeconds
                        );
                    case Constants.TEMP_AK_SECRET_SUB_TYPE:
                        accessKeyId = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_ID_KEY, "");
                        accessKeySecret = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_SECRET_KEY, "");
                        return new BasicSessionCredentials(
                                accessKeyId,
                                accessKeySecret,
                                null,
                                sessionDurationSeconds
                        );
                    case Constants.STS_SECRET_SUB_TYPE:
                        accessKeyId = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_ID_KEY, "");
                        accessKeySecret = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_SECRET_KEY, "");
                        // securityToken
                        String securityToken = "";
                        return new BasicSessionCredentials(
                                accessKeyId,
                                accessKeySecret,
                                securityToken,
                                sessionDurationSeconds
                        );
                    default:
                        throw new RuntimeException("the secret subtype is invalid");
                }
            }
        }
        throw new RuntimeException("the secret type is invalid");
    }
}
