package com.example.can.myapplication;

public class TestCase {


    @Override
    protected void working() {
        Manager.getInstance().waitForCompletion(); 
    }
}
