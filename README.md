xbyak
=====================================================
xbyak for the D programming language
-----------------------------------------------------

I will port the test program and fix bugs little by little.
v0.7250 scope added unittest 10% shorter
v0.7242 
    When using silly, an error occurred unless thread 1 was used.
    dub test -- -t1
    
    After changing Label and LabelManager from class to struct,
    dub test
    worked.


テストプログラム移植とバグ修正を少しずつします
v0.7250 scope 追加　unittest 10%短縮
v0.7242 
    sillyを使いスレッド１でないとエラーになっていました。
    dub test -- -t1
    
    Label, LabelManagerをclassからstructに変更した後からは
    dub test
    で動作しました。

詳細
----
 xbyak Xbyak 7.250（相当）のＤ言語版。
 Version: 0.7250 以降

動作環境
--------
 x86 CPU
 Windows 10(64bit)
 Linux Mint 17(64bit)

開発環境
--------
Windows
 ldc2
 vscode code-d


Original Library
------------
Xbyak([https://github.com/herumi/xbyak](https://github.com/herumi/xbyak))  
