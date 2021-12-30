package com.aliyuncs.auth;

import com.aliyuncs.utils.DateUtils;


public class AlibabaCloudManagedRAMSecretsCredentials extends BasicSessionCredentials {

    private final double expireFact = 0.95;
    private final long nextRotationDurationSeconds;
    private final long lastRefreshTime;

    public AlibabaCloudManagedRAMSecretsCredentials(String accessKeyId, String accessKeySecret, String sessionToken,
                                                    String nextRotationDate, long roleSessionDurationSeconds) {
        super(accessKeyId, accessKeySecret, sessionToken, roleSessionDurationSeconds);
        long nextRotationTime = DateUtils.parseDate(nextRotationDate, DateUtils.TIMEZONE_DATE_PATTERN);
        this.nextRotationDurationSeconds = nextRotationTime - System.currentTimeMillis() / 1000;
        this.lastRefreshTime = System.currentTimeMillis() / 1000;
    }

    @Override
    public boolean willSoonExpire() {
        if (roleSessionDurationSeconds == 0) {
            return false;
        }
        long now = System.currentTimeMillis();
        if (nextRotationDurationSeconds > 0 && nextRotationDurationSeconds < roleSessionDurationSeconds) {
            return nextRotationDurationSeconds * expireFact < (now - lastRefreshTime);
        } else {
            return roleSessionDurationSeconds * expireFact < (now - lastRefreshTime);
        }
    }

}