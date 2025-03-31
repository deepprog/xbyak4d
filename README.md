xbyak
=====================================================
xbyak for the D programming language
-----------------------------------------------------

It has only been compiled.
The instability of unittest seems to have been resolved.

When using silly, an error occurred unless thread 1 was used.
dub test -- -t1

v0.7242 After changing Label and LabelManager from class to struct,
dub test
worked.

I will port the test program and fix bugs little by little.


コンパイルができただけの状態です。
unittestの不安定さは解消されたようです。

sillyを使いスレッド１でないとエラーになっていました。
dub test -- -t1

v0.7242 Label, LabelManagerをclassからstructに変更した後からは
dub test　
で動作しました。

テストプログラム移植とバグ修正を少しずつします

詳細
----
 xbyak Xbyak 7.242（相当）のＤ言語版。
 Version: 0.7242 以降

動作環境
--------
 x86 CPU
 Windows 10(64bit,32bit)
 Linux Mint 17(64bit)

開発環境
--------
Windows
 ldc2
 vscode code-d

Linux
 DMD64 D Compiler v2.070.0-b1(Version: 0.078以降)

Original Library
------------
Xbyak([https://github.com/herumi/xbyak](https://github.com/herumi/xbyak))  
