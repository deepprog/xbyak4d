module gen_vsib;

import std.stdio;
import std.string;
import xbyak;
import test.test_count;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version (XBYAK64)
{
    class TestCode : CodeGenerator
    {
        TestCount tc_;
        string name_;

        this(string name)
        {
            this.tc_.reset();
            name_ = name;
        }

        ~this()
        {
            tc_.end(name_);
        }

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

            tc_.TEST_EQUAL(hexCode, hexStr, file, line);
            size_ = 0;
            return;
        }

    }

    @("gen_vsib") unittest
    {
        writef("%s(%d) : ", __FILE__, __LINE__);
        scope gen_vsib = new GenVsib("gen_vsib");
    }

    class GenVsib : TestCode
    {
        this(string name)
        {
            super(name);

            vgatherdpd(ymm7, ptr[xmm0], ymm4);
            sdump("C4E2DD923C0500000000");
            vgatherdpd(ymm7, ptr[xmm0 * 1], ymm4);
            sdump("C4E2DD923C0500000000");
            vgatherdpd(ymm7, ptr[xmm0 + 4], ymm4);
            sdump("C4E2DD923C0504000000");
            vgatherdpd(ymm7, ptr[xmm0 + eax], ymm4);
            sdump("67C4E2DD923C00");
            vgatherdpd(ymm7, ptr[xmm0 * 4 + ecx], ymm4);
            sdump("67C4E2DD923C81");
            vgatherdpd(ymm7, ptr[xmm3 * 8 + edi + 123], ymm4);
            sdump("67C4E2DD927CDF7B");
            vgatherdpd(ymm7, ptr[xmm2 * 2 + 5], ymm4);
            sdump("C4E2DD923C5505000000");
            vgatherdpd(ymm7, ptr[eax + xmm0], ymm4);
            sdump("67C4E2DD923C00");
            vgatherdpd(ymm7, ptr[esp + xmm2], ymm4);
            sdump("67C4E2DD923C14");
            vgatherqpd(ymm7, ptr[ymm0], ymm4);
            sdump("C4E2DD933C0500000000");
            vgatherqpd(ymm7, ptr[ymm0 * 1], ymm4);
            sdump("C4E2DD933C0500000000");
            vgatherqpd(ymm7, ptr[ymm0 + 4], ymm4);
            sdump("C4E2DD933C0504000000");
            vgatherqpd(ymm7, ptr[ymm0 + eax], ymm4);
            sdump("67C4E2DD933C00");
            vgatherqpd(ymm7, ptr[ymm0 * 4 + ecx], ymm4);
            sdump("67C4E2DD933C81");
            vgatherqpd(ymm7, ptr[ymm3 * 8 + edi + 123], ymm4);
            sdump("67C4E2DD937CDF7B");
            vgatherqpd(ymm7, ptr[ymm2 * 2 + 5], ymm4);
            sdump("C4E2DD933C5505000000");
            vgatherqpd(ymm7, ptr[eax + ymm0], ymm4);
            sdump("67C4E2DD933C00");
            vgatherqpd(ymm7, ptr[esp + ymm2], ymm4);
            sdump("67C4E2DD933C14");
            vgatherdpd(ymm7, ptr[xmm0 + r11], ymm4);
            sdump("C4C2DD923C03");
            vgatherdpd(ymm7, ptr[r13 + xmm15], ymm4);
            sdump("C482DD927C3D00");
            vgatherdpd(ymm7, ptr[123 + rsi + xmm2 * 4], ymm4);
            sdump("C4E2DD927C967B");
        }
    }
}
