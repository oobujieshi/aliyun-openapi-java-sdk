package com.aliyuncs.utils;

import java.net.InetAddress;

public class PingUtils {
    /**
     * ping default time out
     */
    private final static int DEFAULT_PING_TIME_OUT = 2000;

    private PingUtils() {
        // do nothing
    }

    public static boolean ping(String addr) {
        boolean reachable = false;
        try {
            InetAddress address = InetAddress.getByName(addr);
            reachable = address.isReachable(DEFAULT_PING_TIME_OUT);
        } catch (Exception ignore) {
        }
        return reachable;
    }
}
