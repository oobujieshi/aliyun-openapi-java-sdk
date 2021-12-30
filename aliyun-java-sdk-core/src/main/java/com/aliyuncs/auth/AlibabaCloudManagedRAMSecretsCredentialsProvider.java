package com.aliyuncs.auth;


import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.exceptions.ServerException;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.kms.Constants;
import com.aliyuncs.kms.KmsErrorCode;
import com.aliyuncs.kms.model.RegionInfo;
import com.aliyuncs.kms.model.v20160120.GetSecretValueRequest;
import com.aliyuncs.kms.model.v20160120.GetSecretValueResponse;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.aliyuncs.utils.*;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import java.io.File;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class AlibabaCloudManagedRAMSecretsCredentialsProvider implements AlibabaCloudCredentialsProvider {

    public static final int DEFAULT_DURATION_SECONDS = 3600;
    public static final String STAGE_ACS_CURRENT = "ACSCurrent";
    private static final long REQUEST_WAITING_TIME = 10 * 1000L;
    private static final long RETRY_WAITING_TIME = 2000L;
    private long sessionDurationSeconds = DEFAULT_DURATION_SECONDS;
    private BasicSessionCredentials sessionCredentials = null;
    private final String secretName;
    private List<RegionInfo> regionInfoList = new ArrayList<>();
    private Gson gson = new Gson();
    private Map<String, DefaultAcsClient> clientMap = new HashMap<>();
    private AlibabaCloudCredentialsProvider provider;

    public AlibabaCloudManagedRAMSecretsCredentialsProvider(String secretName) {
        if (StringUtils.isEmpty(secretName)) {
            throw new IllegalArgumentException("the param[secretName] is required");
        }
        initClientKey("");
        this.secretName = secretName;
    }

    public AlibabaCloudManagedRAMSecretsCredentialsProvider(String filePath, String secretName) {
        if (StringUtils.isEmpty(secretName)) {
            throw new IllegalArgumentException("the param[secretName] is required");
        }
        initClientKey(filePath);
        this.secretName = secretName;
    }

    public AlibabaCloudManagedRAMSecretsCredentialsProvider withDurationSeconds(long seconds) {
        this.sessionDurationSeconds = seconds;
        return this;
    }

    @Override
    public AlibabaCloudCredentials getCredentials() throws ClientException {
        if (sessionCredentials == null || sessionCredentials.willSoonExpire()) {
            sessionCredentials = getNewCredentials();
        }
        return sessionCredentials;
    }

    private BasicSessionCredentials getNewCredentials() throws ClientException {
        GetSecretValueRequest request = new GetSecretValueRequest();
        request.setVersionStage(STAGE_ACS_CURRENT);
        request.setFetchExtendedConfig(true);
        request.setSecretName(secretName);
        GetSecretValueResponse response = getSecretValue(request);
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
                String nextRotationDate = response.getNextRotationDate();
                if (StringUtils.isEmpty(nextRotationDate)) {
                    throw new RuntimeException("the next rotation date is empty");
                }
                switch (secretSubType) {
                    case Constants.RAM_USER_ACCESS_KEY_SECRET_SUB_TYPE:
                        String accessKeyId = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_ID_KEY, "");
                        String accessKeySecret = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_SECRET_KEY, "");
                        return new AlibabaCloudManagedRAMSecretsCredentials(
                                accessKeyId,
                                accessKeySecret,
                                null,
                                nextRotationDate,
                                sessionDurationSeconds
                        );
                    case Constants.TEMP_AK_SECRET_SUB_TYPE:
                        accessKeyId = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_ID_KEY, "");
                        accessKeySecret = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_SECRET_KEY, "");
                        return new AlibabaCloudManagedRAMSecretsCredentials(
                                accessKeyId,
                                accessKeySecret,
                                null,
                                nextRotationDate,
                                sessionDurationSeconds
                        );
                    case Constants.STS_SECRET_SUB_TYPE:
                        accessKeyId = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_ID_KEY, "");
                        accessKeySecret = secretDataMap.getOrDefault(Constants.SECRET_DATA_ACCESS_KEY_SECRET_KEY, "");
                        // securityToken
                        String securityToken = "";
                        return new AlibabaCloudManagedRAMSecretsCredentials(
                                accessKeyId,
                                accessKeySecret,
                                securityToken,
                                nextRotationDate,
                                sessionDurationSeconds
                        );
                    default:
                        throw new RuntimeException("the secret subtype is invalid");
                }
            }
        }
        throw new RuntimeException("the secret type is invalid");
    }

    public void initClientKey(String filePath) {
        Properties properties = ConfigUtils.loadConfig(filePath, Constants.CREDENTIALS_PROPERTIES_CONFIG_NAME);
        if (properties != null && properties.size() > 0) {
            String password = ClientKeyUtils.getPassword(properties);
            String privateKeyPath = properties.getProperty(Constants.CLIENT_KEY_CONFIG_PRIVATE_KEY_PATH_NAME_KEY);
            if (StringUtils.isEmpty(privateKeyPath)) {
                throw new IllegalArgumentException(String.format("credentials config missing required parameters[%s]", Constants.CLIENT_KEY_CONFIG_PRIVATE_KEY_PATH_NAME_KEY));
            }
            provider = ClientKeyUtils.getCredentialsProvider(privateKeyPath, password);
            try {
                String regionIds = properties.getProperty(Constants.CLIENT_KEY_CONFIG_REGION_ID_KEY);
                List<Map<String, Object>> list = new Gson().fromJson(regionIds, new TypeToken<List<Map<String, Object>>>() {
                }.getType());
                for (Map<String, Object> map : list) {
                    RegionInfo regionInfo = new RegionInfo();
                    regionInfo.setEndpoint(TypeUtils.parseString(map.get(Constants.CLIENT_KEY_CONFIG_ENDPOINT_NAME_KEY)));
                    regionInfo.setRegionId(TypeUtils.parseString(map.get(Constants.CLIENT_KEY_CONFIG_REGION_ID_NAME_KEY)));
                    regionInfo.setVpc(TypeUtils.parseBoolean(map.get(Constants.CLIENT_KEY_CONFIG_REGION_VPC_NAME_KEY)));
                    regionInfoList.add(regionInfo);
                }
            } catch (Exception e) {
                throw new IllegalArgumentException(String.format("credentials config param[%s] is illegal", Constants.CLIENT_KEY_CONFIG_REGION_ID_KEY));
            }
            this.regionInfoList = sortRegionInfos(regionInfoList);
        } else {
            throw new IllegalArgumentException(String.format("can not found config[%s]", filePath + File.separatorChar + Constants.CREDENTIALS_PROPERTIES_CONFIG_NAME));
        }
    }

    private IAcsClient newKmsClientByRegionInfo(RegionInfo regionInfo) {
        if (clientMap.get(regionInfo.getRegionId()) != null) {
            return clientMap.get(regionInfo.getRegionId());
        }
        synchronized (regionInfo) {
            if (clientMap.get(regionInfo.getRegionId()) != null) {
                return clientMap.get(regionInfo.getRegionId());
            }
            IClientProfile profile = DefaultProfile.getProfile(regionInfo.getRegionId());
            if (!StringUtils.isEmpty(regionInfo.getEndpoint())) {
                DefaultProfile.addEndpoint(regionInfo.getRegionId(), Constants.PRODUCT_NAME, regionInfo.getEndpoint());
            } else if (regionInfo.getVpc()) {
                DefaultProfile.addEndpoint(regionInfo.getRegionId(), Constants.PRODUCT_NAME, KmsEndpointUtils.getVPCEndpoint(regionInfo.getRegionId()));
            }
            HttpClientConfig clientConfig = HttpClientConfig.getDefault();
            clientConfig.setIgnoreSSLCerts(true);
            profile.setHttpClientConfig(clientConfig);
            DefaultAcsClient acsClient = new DefaultAcsClient(profile, provider);
            clientMap.put(regionInfo.getRegionId(), acsClient);
        }
        return clientMap.get(regionInfo.getRegionId());
    }

    private List<RegionInfo> sortRegionInfos(List<RegionInfo> regionInfos) {
        List<RegionInfoExtend> regionInfoExtends = new ArrayList<>();
        for (RegionInfo regionInfo : regionInfos) {
            long start = System.currentTimeMillis();
            boolean isReachable;
            if (!StringUtils.isEmpty(regionInfo.getEndpoint())) {
                isReachable = PingUtils.ping(regionInfo.getEndpoint());
            } else if (regionInfo.getVpc()) {
                isReachable = PingUtils.ping(KmsEndpointUtils.getVPCEndpoint(regionInfo.getRegionId()));
            } else {
                isReachable = PingUtils.ping(KmsEndpointUtils.getEndPoint(regionInfo.getRegionId()));
            }
            long escaped = System.currentTimeMillis() - start;
            RegionInfoExtend regionInfoExtend = new RegionInfoExtend(regionInfo);
            regionInfoExtend.setReachable(isReachable);
            regionInfoExtend.setEscaped(escaped);
            regionInfoExtends.add(regionInfoExtend);
        }
        return regionInfoExtends.stream().sorted(Comparator.comparing((RegionInfoExtend regionInfoExtend) -> !regionInfoExtend.getReachable())
                .thenComparing(RegionInfoExtend::getEscaped))
                .map(regionInfoExtend -> new RegionInfo(regionInfoExtend.getRegionId(), regionInfoExtend.getVpc(), regionInfoExtend.getEndpoint()))
                .collect(Collectors.toList());
    }

    class RegionInfoExtend {

        private boolean reachable;
        private long escaped;
        private final String regionId;
        private final boolean vpc;
        private final String endpoint;

        public RegionInfoExtend(RegionInfo regionInfo) {
            this.regionId = regionInfo.getRegionId();
            this.vpc = regionInfo.getVpc();
            this.endpoint = regionInfo.getEndpoint();
        }

        public String getRegionId() {
            return regionId;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public boolean getVpc() {
            return this.vpc;
        }

        public boolean getReachable() {
            return this.reachable;
        }

        public void setReachable(boolean reachable) {
            this.reachable = reachable;
        }

        public long getEscaped() {
            return this.escaped;
        }

        public void setEscaped(long escaped) {
            this.escaped = escaped;
        }
    }

    public GetSecretValueResponse getSecretValue(GetSecretValueRequest req) throws ClientException {
        List<Future<GetSecretValueResponse>> futures = new ArrayList<>();
        CountDownLatch count = null;
        AtomicInteger finished = null;
        ScheduledThreadPoolExecutor pool = null;
        for (int i = 0; i < this.regionInfoList.size(); i++) {
            if (i == 0) {
                try {
                    return getSecretValue(this.regionInfoList.get(i), req);
                } catch (ClientException e) {
                    if (!judgeNeedRecoveryException(e)) {
                        throw e;
                    }
                    count = new CountDownLatch(1);
                    finished = new AtomicInteger(regionInfoList.size());
                }
            }
            if (pool == null) {
                pool = new ScheduledThreadPoolExecutor(regionInfoList.size());
            }
            GetSecretValueRequest request = new GetSecretValueRequest();
            request.setSecretName(req.getSecretName());
            request.setVersionStage(req.getVersionStage());
            request.setFetchExtendedConfig(true);
            Future<GetSecretValueResponse> future = pool.submit(new RetryGetSecretValueTask(request, regionInfoList.get(i), count, finished));
            futures.add(future);
        }

        GetSecretValueResponse getSecretValueResponse;
        try {
            count.await(REQUEST_WAITING_TIME, TimeUnit.MILLISECONDS);
            for (Future<GetSecretValueResponse> future : futures) {
                try {
                    if (!future.isDone()) {
                        future.cancel(true);
                    } else {
                        getSecretValueResponse = future.get();
                        if (getSecretValueResponse != null) {
                            return getSecretValueResponse;
                        }
                    }
                } catch (InterruptedException | ExecutionException e) {
                }
            }
        } catch (InterruptedException e) {
            throw new ClientException(e);
        } finally {
            if (count.getCount() > 0) {
                count.countDown();
            }
            if (pool != null) {
                pool.shutdown();
            }

        }
        throw new ClientException(KmsErrorCode.SDK_READ_TIMEOUT, String.format("retry get secret value task fail with secretName[%s]", req.getSecretName()));
    }

    private GetSecretValueResponse getSecretValue(RegionInfo regionInfo, GetSecretValueRequest req) throws ClientException {
        return newKmsClientByRegionInfo(regionInfo).getAcsResponse(req);
    }

    private boolean judgeNeedRecoveryException(ClientException e) {
        if (KmsErrorCode.SDK_READ_TIMEOUT.equals(e.getErrCode()) || KmsErrorCode.SDK_SERVER_UNREACHABLE.equals(e.getErrCode()) ||
                KmsErrorCode.REJECTED_THROTTLING.equals(e.getErrCode()) || KmsErrorCode.SERVICE_UNAVAILABLE_TEMPORARY.equals(e.getErrCode()) || KmsErrorCode.INTERNAL_FAILURE.equals(e.getErrCode())) {
            return true;
        }
        return false;
    }

    class RetryGetSecretValueTask implements Callable<GetSecretValueResponse> {
        final private static int MAX_RETRY_TIME = 3;
        final private GetSecretValueRequest req;
        final private RegionInfo regionInfo;
        final private CountDownLatch countDownLatch;
        final private AtomicInteger finished;

        public RetryGetSecretValueTask(GetSecretValueRequest req, RegionInfo regionInfo, CountDownLatch countDownLatch, AtomicInteger finished) {
            this.req = req;
            this.regionInfo = regionInfo;
            this.countDownLatch = countDownLatch;
            this.finished = finished;
        }

        @Override
        public GetSecretValueResponse call() throws Exception {
            try {
                GetSecretValueResponse resp = retryGetSecretValue(req, regionInfo);
                countDownLatch.countDown();
                return resp;
            } catch (Exception e) {
                return null;
            } finally {
                if (finished.decrementAndGet() == 0) {
                    countDownLatch.countDown();
                }
            }
        }

        private GetSecretValueResponse retryGetSecretValue(GetSecretValueRequest req, RegionInfo regionInfo) throws ClientException {
            for (int i = 0; i < MAX_RETRY_TIME; i++) {
                if (countDownLatch.getCount() == 0) {
                    return null;
                }
                try {
                    Thread.sleep(RETRY_WAITING_TIME);
                } catch (InterruptedException ignore) {
                }
                try {
                    return getSecretValue(regionInfo, req);
                } catch (ClientException e) {
                    if (!judgeNeedRecoveryException(e)) {
                        throw e;
                    }
                }
                i++;
            }
            throw new ClientException(KmsErrorCode.SDK_READ_TIMEOUT, "times limit exceeded");
        }
    }
}
