package com.mixi.injectdemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

import java.io.DataOutputStream;
import java.io.IOException;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        rootCommand("su");
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());
        new Test2().callTest2();
        new Test2().sayHelloe();
        new Test2().saySB();

    }


    public native String stringFromJNI();

    static {
        System.loadLibrary("native-lib");
    }

    public static boolean rootCommand(String command) {
        Process process = null;
        DataOutputStream dos = null;
        try {
            process = Runtime.getRuntime().exec("su");
            /*dos = new DataOutputStream(process.getOutputStream());
            dos.writeBytes(command +"\n");
            dos.writeBytes("exit\n");
            dos.flush();
            process.waitFor();*/
        } catch (Exception e) {
            return false;
        }
        return true;
    }

}
