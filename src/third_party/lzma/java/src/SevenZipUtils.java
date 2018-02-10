/**
 * Copyright (C) 2014 Baidu, Inc. All Rights Reserved.
 */
package com.samtest;

import java.io.File;
import java.io.FilenameFilter;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.os.Environment;
import android.os.StatFs;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;

/**
 * 7Z Utils
 */
public class SevenZipUtils {

    private static final boolean DEBUG = false;
    private static final String TAG = "SevenZipUtils";

    static {
        try {
            System.loadLibrary("lzma");
        } catch (Throwable e) {
            Log.e(TAG, "failed to load lzma library: " + e) ;
        }
    }

    private static void LogI(String msg) {
        if (DEBUG) {
            Log.i(TAG, msg);
        }
    }

    private SevenZipUtils() { }


    private static SevenZipUtils mInstance = null;

    public synchronized static SevenZipUtils getInstance() {
        if (mInstance == null) {
            mInstance = new SevenZipUtils();
        }
        return mInstance;
    }

    private String checkTimestamp(Context ctx, String dst) {
        final String prefix = "samtest-";
        File output = new File(dst);
        if (output == null || !output.exists() || !output.isDirectory()) {
            return prefix;
        }

        PackageInfo pi = null;
        try {
            PackageManager pm = ctx.getPackageManager();
            pi = pm.getPackageInfo(ctx.getPackageName(), 0);

            if (pi == null) {
                return prefix;
            }
        } catch (PackageManager.NameNotFoundException e) {
            return prefix;
        } catch (Exception oe) {
            return prefix;
        }

        String expectedTimestamp = prefix + pi.versionCode + "-" + pi.lastUpdateTime;

        String[] timestamps = output.list(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.startsWith(prefix);
            }
        });

        if (timestamps == null) {
            return expectedTimestamp;
        }
        for (int i = 0; i < timestamps.length; ++i) {
            if (expectedTimestamp.equals(timestamps[i])) {
                return null;
            }
            new File(output, timestamps[i]).delete();
        }

        return expectedTimestamp;
    }

    public synchronized boolean prepare(Context context, String dest) {
        Context ctx = context.getApplicationContext();
        // check timestmap
        String timeStamp = checkTimestamp(ctx, dest);
        if (timeStamp == null) {
            return false;
        }

        return true;
    }

    public void extract(String filePath, String dstPath) {
        try {
            if (nativeExtract(filePath, dstPath) == 0) {
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

///////////////////////////////////////////////////////////////////////
// native methods
///////////////////////////////////////////////////////////////////////
    private native int nativeExtract(String filePath, String outPath);
}

