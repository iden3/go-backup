## Gomobile instalation
```
$ go get golang.org/x/mobile/cmd/gomobile
$ gomobile init
```
## Install Android Studio (on Ubuntu 20.04):
```
$ sudo apt install openjdk-11-jdk
$ sudo snap install android-studio --classic
```
## Install Android NDK:

https://developer.android.com/ndk

You may need to configure these enviroment variables:
```
export GOPATH=~/go
export PATH=$PATH:$GOPATH/bin
export ANDROID_NDK_HOME= {PATH to Android NDK}
export ANDROID_HOME= {PATH to Android SDK}
```

## aar generation
```
$ gomobile bind -o app/backuplib.aar -target=android ../backuplib/
```

## Use of .aar in Android project

Edit android\app\build.gradle adding:
```
+ repositories {
+    flatDir {
+        dirs '.'
+    }
+ }

dependencies {
...
+    implementation (name:'backuplib', ext:'aar')
}
```
