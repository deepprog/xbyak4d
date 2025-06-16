module test.nm32.nm32_gen01;

import std.stdio;
import std.string;
import std.exception;
import xbyak;
import test.test_count;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version (XBYAK32)
{

    @("nm32_gen01")
    unittest
    {
        class gen01 : CodeGenerator
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

            ~this()
            {
                testCount.end("nm64_gen01");
            }

            this()
            {
                testCount.reset();

                push(12345678);
                sdump("684E61BC00");
                push(4);
                sdump("6A04");
                push(word, 1000);
                sdump("6668E803");
                push(dx);
                sdump("6652");
                push(ax);
                sdump("6650");
                push(word[esi]);
                sdump("66FF36");
                pop(cx);
                sdump("6659");
                pop(ax);
                sdump("6658");
                pop(word[esi]);
                sdump("668F06");
                push(edi);
                sdump("57");
                push(eax);
                sdump("50");
                push(12345678);
                sdump("684E61BC00");
                push(dword[ebp * 2]);
                sdump("FF742D00");
                pop(ecx);
                sdump("59");
                pop(eax);
                sdump("58");
                pop(dword[ebp * 2]);
                sdump("8F442D00");
                test(ptr[eax + ecx + 3], ecx);
                sdump("854C0803");
                test(ptr[eax + ecx + 3], eax);
                sdump("85440803");
                test(esp, ecx);
                sdump("85CC");
                test(ecx, eax);
                sdump("85C1");
                test(eax, esi);
                sdump("85F0");
                test(eax, eax);
                sdump("85C0");
                test(ptr[eax + ecx + 3], bx);
                sdump("66855C0803");
                test(ptr[eax + ecx + 3], ax);
                sdump("6685440803");
                test(dx, sp);
                sdump("6685E2");
                test(si, ax);
                sdump("6685C6");
                test(ax, si);
                sdump("6685F0");
                test(ax, ax);
                sdump("6685C0");
                test(ptr[eax + ecx + 3], cl);
                sdump("844C0803");
                test(ptr[eax + ecx + 3], al);
                sdump("84440803");
                test(cl, ch);
                sdump("84E9");
                test(cl, al);
                sdump("84C1");
                test(al, cl);
                sdump("84C8");
                test(al, al);
                sdump("84C0");
                test(ecx, 4);
                sdump("F7C104000000");
                test(edi, 0xda);
                sdump("F7C7DA000000");
                test(eax, 4);
                sdump("A904000000");
                test(eax, 0xda);
                sdump("A9DA000000");
                test(dl, 4);
                sdump("F6C204");
                test(cl, 0xda);
                sdump("F6C1DA");
                test(si, 4);
                sdump("66F7C60400");
                test(si, 0xda);
                sdump("66F7C6DA00");
                test(ax, 4);
                sdump("66A90400");
                test(ax, 0xda);
                sdump("66A9DA00");
                test(al, 4);
                sdump("A804");
                test(al, 0xda);
                sdump("A8DA");
                test(byte_[eax + edx], 4);
                sdump("F6041004");
                test(byte_[eax + edx], 0xda);
                sdump("F60410DA");
                test(word[esi], 4);
                sdump("66F7060400");
                test(word[esi], 0xda);
                sdump("66F706DA00");
                test(dword[ebp * 2], 4);
                sdump("F7442D0004000000");
                test(dword[ebp * 2], 0xda);
                sdump("F7442D00DA000000");
            }
        }

        scope g1 = new gen01();
    }

}
