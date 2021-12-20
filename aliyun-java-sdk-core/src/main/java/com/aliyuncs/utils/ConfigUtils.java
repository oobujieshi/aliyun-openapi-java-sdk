package com.aliyuncs.utils;

import com.google.gson.GsonBuilder;

import java.io.*;
import java.util.Properties;

public class ConfigUtils {

    private ConfigUtils() {
        // do nothing
    }

    public static <T> T readJsonObject(String filePath, Class<T> type) {
        File file = new File(filePath);
        if (!file.exists()) {
            return null;
        }
        try (
                FileReader fileReader = new FileReader(file);
                BufferedReader reader = new BufferedReader(fileReader);
        ) {
            T json = new GsonBuilder().setPrettyPrinting().create().fromJson(reader, type);
            return json;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static Properties loadConfig(String filePath, String configName) {
        Properties properties = new Properties();
        if (!StringUtils.isEmpty(filePath)) {
            try (InputStream in = new FileInputStream(filePath + System.lineSeparator() + configName)) {
                if (in == null) {
                    return null;
                }
                properties.load(in);
                return properties;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        try (InputStream in = ConfigUtils.class.getClassLoader().getResourceAsStream(configName)) {
            if (in == null) {
                return null;
            }
            properties.load(in);
            return properties;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
