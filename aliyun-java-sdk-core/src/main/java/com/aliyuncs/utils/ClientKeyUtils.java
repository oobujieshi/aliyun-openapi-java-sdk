package com.aliyuncs.utils;

import com.aliyuncs.auth.AlibabaCloudCredentialsProvider;
import com.aliyuncs.auth.KeyPairCredentials;
import com.aliyuncs.kms.Constants;
import com.aliyuncs.kms.model.ClientKeyCredentialsProvider;
import com.aliyuncs.kms.model.ClientKeyInfo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class ClientKeyUtils {

    public final static String PKCS12 = "PKCS12";

    private ClientKeyUtils() {
        // do nothing
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
        String passwordFromEnvName = (String) envMap.getOrDefault(Constants.ENV_CLIENT_KEY_PASSWORD_FROM_ENV_VARIABLE_NAME, "");
        String password = "";
        if (!StringUtils.isEmpty(passwordFromEnvName)) {
            password = System.getenv(passwordFromEnvName);
        }
        if (StringUtils.isEmpty(password)) {
            String passwordFilePath = (String) envMap.getOrDefault(Constants.ENV_CLIENT_KEY_PASSWORD_FROM_FILE_PATH_NAME, "");
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
