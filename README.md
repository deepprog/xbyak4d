xbyak
=====================================================
xbyak for the D programming language
-----------------------------------------------------
Details
----
xbyak D language port of Xbyak 7.260 (equivalent).
Version: 0.7260 or later (tag v0.1.1)


v0.1.1 Unit test created
v0.7260
    dub test

I will port the test program and fix bugs little by little.
v0.7250 scope added unittest 10% shorter
v0.7242 
    When using silly, an error occurred unless thread 1 was used.
    dub test -- -t1
    
    After changing Label and LabelManager from class to struct,
    dub test
    worked.

Original Library
------------
Xbyak([https://github.com/herumi/xbyak](https://github.com/herumi/xbyak))  




詳細
----
xbyak Xbyak 7.260（同等）のD言語移植版。
バージョン: 0.7260 以降 (タグ v0.1.1)

v0.1.1 ユニットテスト作成
v0.7260
    dub test

テストプログラム移植とバグ修正を少しずつします
v0.7250 scope 追加　unittest 10%短縮
v0.7242 
    sillyを使いスレッド１でないとエラーになっていました。
    dub test -- -t1
    
    Label, LabelManagerをclassからstructに変更した後からは
    dub test
    で動作しました。


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
