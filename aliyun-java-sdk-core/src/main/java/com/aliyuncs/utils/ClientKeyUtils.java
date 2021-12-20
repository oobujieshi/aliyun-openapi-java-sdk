package com.aliyuncs.utils;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.auth.AlibabaCloudCredentialsProvider;
import com.aliyuncs.auth.KeyPairCredentials;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.kms.model.ClientKeyCredentialsProvider;
import com.aliyuncs.kms.model.ClientKeyInfo;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;

public class ClientKeyUtils {

    private final static String PKCS12 = "PKCS12";

    /**
     * client_key_password_from_env_variable key
     */
    private final static String ENV_CLIENT_KEY_PASSWORD_FROM_ENV_VARIABLE_NAME = "client_key_password_from_env_variable";

    /**
     * client_key_password_from_file_path key
     */
    private final static String ENV_CLIENT_KEY_PASSWORD_FROM_FILE_PATH_NAME = "client_key_password_from_file_path";

    /**
     * credentials配置文件名称
     */
    private final static String CREDENTIALS_PROPERTIES_CONFIG_NAME = "secretsmanager.properties";

    /**
     * 环境变量credentials_client_key_private_key_path key
     */
    private final static String CLIENT_KEY_CONFIG_PRIVATE_KEY_PATH_NAME_KEY = "client_key_private_key_path";

    /**
     * client key config region_id key
     */
    private final static String CLIENT_KEY_CONFIG_REGION_ID_KEY = "region_id";

    private ClientKeyUtils() {
        // do nothing
    }

    public static IAcsClient getAcsClientByClientKey(String filePath) {
        Properties properties = ConfigUtils.loadConfig(filePath, CREDENTIALS_PROPERTIES_CONFIG_NAME);
        if (properties != null && properties.size() > 0) {
            String password = ClientKeyUtils.getPassword(properties);
            String privateKeyPath = properties.getProperty(CLIENT_KEY_CONFIG_PRIVATE_KEY_PATH_NAME_KEY);
            if (StringUtils.isEmpty(privateKeyPath)) {
                throw new IllegalArgumentException(String.format("credentials config missing required parameters[%s]", CLIENT_KEY_CONFIG_PRIVATE_KEY_PATH_NAME_KEY));
            }
            AlibabaCloudCredentialsProvider provider = getCredentialsProvider(privateKeyPath, password);
            IClientProfile profile = DefaultProfile.getProfile(properties.getProperty(CLIENT_KEY_CONFIG_REGION_ID_KEY));
            HttpClientConfig clientConfig = HttpClientConfig.getDefault();
            clientConfig.setIgnoreSSLCerts(true);
            profile.setHttpClientConfig(clientConfig);
            return new DefaultAcsClient(profile, provider);
        } else {
            throw new IllegalArgumentException(String.format("can not found config[s%]", filePath + File.separatorChar + CREDENTIALS_PROPERTIES_CONFIG_NAME));
        }
    }

    public static String getPrivateKeyPemFromPk12(byte[] pk12, String password) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance(PKCS12);
        keyStore.load(new ByteArrayInputStream(pk12), password.toCharArray());
        Enumeration<String> e = keyStore.aliases();
        String alias = e.nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public static String getPassword(Map envMap) {
        String passwordFromEnvName = (String) envMap.getOrDefault(ENV_CLIENT_KEY_PASSWORD_FROM_ENV_VARIABLE_NAME, "");
        String password = "";
        if (!StringUtils.isEmpty(passwordFromEnvName)) {
            password = System.getenv(passwordFromEnvName);
        }
        if (StringUtils.isEmpty(password)) {
            String passwordFilePath = (String) envMap.getOrDefault(ENV_CLIENT_KEY_PASSWORD_FROM_FILE_PATH_NAME, "");
            if (!StringUtils.isEmpty(passwordFilePath)) {
                try {
                    byte[] bytes = Files.readAllBytes(Paths.get(passwordFilePath));
                    password = new String(bytes);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        if (StringUtils.isEmpty(password)) {
            throw new IllegalArgumentException("client key password is not provided");
        }
        return password;
    }

    public static AlibabaCloudCredentialsProvider getCredentialsProvider(String clientKeyPath, String password) {
        ClientKeyInfo clientKeyInfo = ConfigUtils.readJsonObject(clientKeyPath, ClientKeyInfo.class);
        if (clientKeyInfo != null) {
            byte[] pk12 = Base64.getDecoder().decode(clientKeyInfo.getPrivateKeyData());
            try {
                String privateKey = ClientKeyUtils.getPrivateKeyPemFromPk12(pk12, password);
                return new ClientKeyCredentialsProvider(new KeyPairCredentials(clientKeyInfo.getKeyId(), privateKey));
            } catch (Exception e) {
                throw new RuntimeException("resolve client key fail", e);
            }
        } else {
            throw new RuntimeException("client key is invalid");
        }
    }

}
