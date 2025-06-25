module xed_apx;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;
import xbyak;

import test.test_count;

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
        scope c = new Code();
    }

    class TestCode : CodeGenerator
    {
        TestCount testCount;

        void sdump(string hexStr, string file = __FILE__, size_t line = __LINE__)
        {
            if (hexStr.length == 0)
            {
                dump();
                size_ = 0;
                return;
            }

            const size_t n = this.getSize();
            auto ctbl = this.getCode();

            string hexCode;
            for (size_t i = 0; i < n; i++)
            {
                hexCode ~= format("%02X", ctbl[i]);
            }

            testCount.TEST_EQUAL(hexCode, hexStr, file, line);
            size_ = 0;
            return;
        }

        this()
        {
            testCount.reset();

            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);
        }

        ~this()
        {
            testCount.end(__FILE__);
        }

    }

    class Code : TestCode
    {
        this()
        {
            sal(rax, r8, 1);
            sdump("62D4FC18D1E0");
            sar(rax, r9, 4);
            sdump("62D4FC18C1F904");
            shl(rax, rdi, 8);
            sdump("62F4FC18C1E708");
            shr(rax, rsi, 12);
            sdump("62F4FC18C1EE0C");
            rcl(rax, r10, 16);
            sdump("62D4FC18C1D210");
            rcr(rax, r11, 20);
            sdump("62D4FC18C1DB14");
            rol(rax, r14, 24);
            sdump("62D4FC18C1C618");
            ror(rax, r15, 28);
            sdump("62D4FC18C1CF1C");
            sal(rcx, qword[r8], 32);
            sdump("62D4F418C12020");
            sar(rcx, qword[r9], 36);
            sdump("62D4F418C13924");
            sal(rcx, qword[rdi], 40);
            sdump("62F4F418C12728");
            sar(rcx, qword[rsi], 44);
            sdump("62F4F418C13E2C");
            rcl(rcx, qword[r10], 48);
            sdump("62D4F418C11230");
            rcr(rcx, qword[r11], 52);
            sdump("62D4F418C11B34");
            rol(rcx, qword[r14], 56);
            sdump("62D4F418C10638");
            ror(rcx, qword[r15], 60);
            sdump("62D4F418C10F3C");

            imul(rax, rdx, r10);
            sdump("62D4FC18AFD2");
            imul(rcx, r15, qword[rdi]);
            sdump("6274F418AF3F");

        }
    }
}
