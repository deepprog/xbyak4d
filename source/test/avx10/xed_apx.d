module xed_apx;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;
import xbyak;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version (XBYAK64)
{
    @("xed_apx")
    unittest
    {
        xed_apx();
    }

    void xed_apx()
    {
        writeln("xed_apx");
        scope Code c = new Code();
    }

    class Code : CodeGenerator
    {
        this()
        {
            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            sal(rax, r8, 1);
            sar(rax, r9, 4);
            shl(rax, rdi, 8);
            shr(rax, rsi, 12);
            rcl(rax, r10, 16);
            rcr(rax, r11, 20);
            rol(rax, r14, 24);
            ror(rax, r15, 28);
            sal(rcx, qword[r8], 32);
            sar(rcx, qword[r9], 36);
            sal(rcx, qword[rdi], 40);
            sar(rcx, qword[rsi], 44);
            rcl(rcx, qword[r10], 48);
            rcr(rcx, qword[r11], 52);
            rol(rcx, qword[r14], 56);
            ror(rcx, qword[r15], 60);

            imul(rax, rdx, r10);
            imul(rcx, r15, qword[rdi]);
        }
    }
}
