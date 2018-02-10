package com.samtest;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.io.File;

public class Manager {
    private static final String TAG = "BlinkUnzipManager";
    private static Manager sInstance = null;
    private Task mUnzipTask;
    int TIME_WAIT = 15000; // millis
    
    private Manager() {}

    public static synchronized Manager getInstance() {
        if (sInstance == null) {
            sInstance = new Manager();
        }
        return sInstance;
    }

    private class Task extends Thread {

        private Context mContext;
        private File mSrc;
        private File mDst;

        Task(Context context, File srcPath, File dstPath) {
            mContext = context;
            mSrc = srcPath;
            mDst = dstPath;
        }

        private void onError() {

        }

        @Override
        public void run() {
            try {


                Log.i(TAG, "[perf][startup][unzip] begin.");
                SevenZipUtils.getInstance().extract(mSrc.toString(), mDst.toString());
                Log.i(TAG, "[perf][startup][unzip] finish.");
                onPostExecute();
            } catch (Throwable t) {
                onError();
            }
        }

        protected void onPostExecute() {
        }
    }


    private synchronized void ensureUnzipTaskStarted() {
        if (mUnzipTask == null) {
            return;
        }

        if (!mUnzipTask.isAlive() && mUnzipTask.getState() != Thread.State.TERMINATED) {
            mUnzipTask.start();
        }
    }

    public synchronized void startDecompressLib(Context ctx, File srcPath, File dstPath) {
        if(!SevenZipUtils.getInstance().prepare(ctx, dstPath.toString())) {
            return;
        }

        ensureUnzipTaskStarted();
        mUnzipTask = new Task(ctx, srcPath, dstPath);
        ensureUnzipTaskStarted();
    }

    public synchronized void startDecompressLib(Context ctx, String srcPath, String dstPath) {
        startDecompressLib(ctx, new File(srcPath), new File(dstPath));
    }

    public void loadLibrary() {

    }

    public synchronized void waitForCompletion() throws Exception {
        try {
            ensureUnzipTaskStarted();
            mUnzipTask.join(TIME_WAIT);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            mUnzipTask = null;
        }
    }
}
