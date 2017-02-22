# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in E:\developersoft\android-sdk-windows-new02/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Add any project specific keep options here:

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}
-optimizationpasses 5 #指定代码的压缩级别
-dontusemixedcaseclassnames #是否使用大小写混合
-dontpreverify #混淆时是否预做校验
-verbose #混淆时是否记录日志

-optimizations !code/simplification/arithmetic,!field #混淆时所用的算法
-keep public class * extends android.app.Activity #保持那些类不被混淆
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceive
-keep public class * extends android.content.ContentProvicer
-keep public class * extends android.preference.Preference
-keep public class com.mixi.injectdemo.Test3

-keepclasseswithmembernames class *{ #保持 native 方法不被混淆
     native <methods>;
}
-keepclasseswithmembers class *{ #保持自定义控件类不被混淆
      public <init>(android.content.Context,android.util.AttributeSet);
}
-keepclasseswithmembers class *{
      public <init>(android.content.Context, android.util.AttributeSet, int);
}
-keepclassmembers class * extends android.app.Activity{
       public void *(android.view.View);
}

