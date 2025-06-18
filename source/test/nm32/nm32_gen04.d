module test.nm32.nm32_gen04;

import std.stdio;
import std.string;
import std.exception;
import xbyak;
import test.test_count;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version (XBYAK32)
{

    @("nm32_gen04")
    unittest
    {
        class gen04 : CodeGenerator
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
                testCount.end("nm32_gen04");
            }

            this()
            {
                testCount.reset();

                psllw(mm5, 4);
                sdump("0F71F504");
                psllw(mm6, 0xda);
                sdump("0F71F6DA");
                psllw(xmm3, 4);
                sdump("660F71F304");
                psllw(xmm6, 0xda);
                sdump("660F71F6DA");
                pslld(mm5, 4);
                sdump("0F72F504");
                pslld(mm2, 0xda);
                sdump("0F72F2DA");
                pslld(xmm5, 4);
                sdump("660F72F504");
                pslld(xmm4, 0xda);
                sdump("660F72F4DA");
                psllq(mm1, 4);
                sdump("0F73F104");
                psllq(mm0, 0xda);
                sdump("0F73F0DA");
                psllq(xmm5, 4);
                sdump("660F73F504");
                psllq(xmm4, 0xda);
                sdump("660F73F4DA");
                psraw(mm6, 4);
                sdump("0F71E604");
                psraw(mm6, 0xda);
                sdump("0F71E6DA");
                psraw(xmm2, 4);
                sdump("660F71E204");
                psraw(xmm0, 0xda);
                sdump("660F71E0DA");
                psrad(mm1, 4);
                sdump("0F72E104");
                psrad(mm5, 0xda);
                sdump("0F72E5DA");
                psrad(xmm6, 4);
                sdump("660F72E604");
                psrad(xmm6, 0xda);
                sdump("660F72E6DA");
                psrlw(mm0, 4);
                sdump("0F71D004");
                psrlw(mm4, 0xda);
                sdump("0F71D4DA");
                psrlw(xmm1, 4);
                sdump("660F71D104");
                psrlw(xmm2, 0xda);
                sdump("660F71D2DA");
                psrld(mm3, 4);
                sdump("0F72D304");
                psrld(mm0, 0xda);
                sdump("0F72D0DA");
                psrld(xmm1, 4);
                sdump("660F72D104");
                psrld(xmm6, 0xda);
                sdump("660F72D6DA");
                psrlq(mm1, 4);
                sdump("0F73D104");
                psrlq(mm0, 0xda);
                sdump("0F73D0DA");
                psrlq(xmm1, 4);
                sdump("660F73D104");
                psrlq(xmm7, 0xda);
                sdump("660F73D7DA");
                pslldq(xmm3, 4);
                sdump("660F73FB04");
                pslldq(xmm6, 0xda);
                sdump("660F73FEDA");
                psrldq(xmm4, 4);
                sdump("660F73DC04");
                psrldq(xmm3, 0xda);
                sdump("660F73DBDA");
                pmovmskb(ebp, mm7);
                sdump("0FD7EF");
                pmovmskb(edx, xmm5);
                sdump("660FD7D5");
                pmovmskb(eax, mm2);
                sdump("0FD7C2");
                pmovmskb(eax, xmm1);
                sdump("660FD7C1");
                pextrw(esp, mm0, 4);
                sdump("0FC5E004");
                pextrw(ebp, mm3, 0xda);
                sdump("0FC5EBDA");
                pextrw(ebx, xmm2, 4);
                sdump("660FC5DA04");
                pextrw(ecx, xmm6, 0xda);
                sdump("660FC5CEDA");
                pextrw(eax, mm3, 4);
                sdump("0FC5C304");
                pextrw(eax, mm6, 0xda);
                sdump("0FC5C6DA");
                pextrw(eax, xmm3, 4);
                sdump("660FC5C304");
                pextrw(eax, xmm6, 0xda);
                sdump("660FC5C6DA");
                pinsrw(mm2, ptr[eax + ecx + 3], 4);
                sdump("0FC454080304");
                pinsrw(mm0, ptr[eax + ecx + 3], 0xda);
                sdump("0FC4440803DA");
                pinsrw(mm1, edx, 4);
                sdump("0FC4CA04");
                pinsrw(mm6, edi, 0xda);
                sdump("0FC4F7DA");
                pinsrw(mm4, eax, 4);
                sdump("0FC4E004");
                pinsrw(mm5, eax, 0xda);
                sdump("0FC4E8DA");
                pinsrw(xmm5, ptr[eax + ecx + 3], 4);
                sdump("660FC46C080304");
                pinsrw(xmm0, ptr[eax + ecx + 3], 0xda);
                sdump("660FC4440803DA");
                pinsrw(xmm7, ecx, 4);
                sdump("660FC4F904");
                pinsrw(xmm3, ebp, 0xda);
                sdump("660FC4DDDA");
                pinsrw(xmm1, eax, 4);
                sdump("660FC4C804");
                pinsrw(xmm5, eax, 0xda);
                sdump("660FC4E8DA");
                pshufw(mm1, mm6, 4);
                sdump("0F70CE04");
                pshufw(mm4, mm5, 0xda);
                sdump("0F70E5DA");
                pshufw(mm2, ptr[eax + ecx + 3], 4);
                sdump("0F7054080304");
                pshufw(mm1, ptr[eax + ecx + 3], 0xda);
                sdump("0F704C0803DA");
                pshuflw(xmm5, xmm5, 4);
                sdump("F20F70ED04");
                pshuflw(xmm3, xmm6, 0xda);
                sdump("F20F70DEDA");
                pshuflw(xmm2, ptr[eax + ecx + 3], 4);
                sdump("F20F7054080304");
                pshuflw(xmm2, ptr[eax + ecx + 3], 0xda);
                sdump("F20F70540803DA");
                pshufhw(xmm6, xmm1, 4);
                sdump("F30F70F104");
                pshufhw(xmm1, xmm7, 0xda);
                sdump("F30F70CFDA");
                pshufhw(xmm1, ptr[eax + ecx + 3], 4);
                sdump("F30F704C080304");
                pshufhw(xmm6, ptr[eax + ecx + 3], 0xda);
                sdump("F30F70740803DA");
                pshufd(xmm4, xmm2, 4);
                sdump("660F70E204");
                pshufd(xmm2, xmm3, 0xda);
                sdump("660F70D3DA");
                pshufd(xmm0, ptr[eax + ecx + 3], 4);
                sdump("660F7044080304");
                pshufd(xmm4, ptr[eax + ecx + 3], 0xda);
                sdump("660F70640803DA");
                movdqa(xmm7, xmm6);
                sdump("660F6FFE");
                movdqa(xmm1, ptr[eax + ecx + 3]);
                sdump("660F6F4C0803");
                movdqa(ptr[eax + ecx + 3], xmm0);
                sdump("660F7F440803");
                movdqu(xmm6, xmm3);
                sdump("F30F6FF3");
                movdqu(xmm2, ptr[eax + ecx + 3]);
                sdump("F30F6F540803");
                movdqu(ptr[eax + ecx + 3], xmm7);
                sdump("F30F7F7C0803");
                movaps(xmm5, xmm4);
                sdump("0F28EC");
                movaps(xmm6, ptr[eax + ecx + 3]);
                sdump("0F28740803");
                movaps(ptr[eax + ecx + 3], xmm1);
                sdump("0F294C0803");
                movss(xmm7, xmm5);
                sdump("F30F10FD");
                movss(xmm4, ptr[eax + ecx + 3]);
                sdump("F30F10640803");
                movss(ptr[eax + ecx + 3], xmm5);
                sdump("F30F116C0803");
                movups(xmm2, xmm7);
                sdump("0F10D7");
                movups(xmm5, ptr[eax + ecx + 3]);
                sdump("0F106C0803");
                movups(ptr[eax + ecx + 3], xmm1);
                sdump("0F114C0803");
                movapd(xmm7, xmm6);
                sdump("660F28FE");
                movapd(xmm5, ptr[eax + ecx + 3]);
                sdump("660F286C0803");
                movapd(ptr[eax + ecx + 3], xmm1);
                sdump("660F294C0803");
                movsd(xmm2, xmm5);
                sdump("F20F10D5");
                movsd(xmm4, ptr[eax + ecx + 3]);
                sdump("F20F10640803");
                movsd(ptr[eax + ecx + 3], xmm7);
                sdump("F20F117C0803");
                movupd(xmm2, xmm3);
                sdump("660F10D3");
                movupd(xmm3, ptr[eax + ecx + 3]);
                sdump("660F105C0803");
                movupd(ptr[eax + ecx + 3], xmm4);
                sdump("660F11640803");
                movq2dq(xmm7, mm3);
                sdump("F30FD6FB");
                movdq2q(mm7, xmm1);
                sdump("F20FD6F9");

            }
        }

        scope g4 = new gen04();
    }

}
