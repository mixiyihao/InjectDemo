package com.mixi.injectdemo;

/**
 * Created by mixi on 2016/10/17.
 */

public class Test2 {
    public Test2(){
        System.out.println("Hello Test2");
    }

    public void sayHelloe(){
        System.out.println("hello ");
    }
    public void saySB(){
        System.out.println("hello S.B");
    }
    public void callTest2(){
        Test3 test3 = new Test3();
        test3.test();
    }

}
