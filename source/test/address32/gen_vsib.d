module test.address32.gen_vsib;

import std.stdio;
import std.string;
import xbyak;
import test.test_count;

version (X86) version = XBYAK32;
version (X86_64) version = XBYAK64;

version (XBYAK32)
{
    @("gen_vsib") unittest
    {
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
            sdump("C4E2DD923C00");
            vgatherdpd(ymm7, ptr[xmm0 * 4 + ecx], ymm4);
            sdump("C4E2DD923C81");
            vgatherdpd(ymm7, ptr[xmm3 * 8 + edi + 123], ymm4);
            sdump("C4E2DD927CDF7B");
            vgatherdpd(ymm7, ptr[xmm2 * 2 + 5], ymm4);
            sdump("C4E2DD923C5505000000");
            vgatherdpd(ymm7, ptr[eax + xmm0], ymm4);
            sdump("C4E2DD923C00");
            vgatherdpd(ymm7, ptr[esp + xmm2], ymm4);
            sdump("C4E2DD923C14");
            vgatherqpd(ymm7, ptr[ymm0], ymm4);
            sdump("C4E2DD933C0500000000");
            vgatherqpd(ymm7, ptr[ymm0 * 1], ymm4);
            sdump("C4E2DD933C0500000000");
            vgatherqpd(ymm7, ptr[ymm0 + 4], ymm4);
            sdump("C4E2DD933C0504000000");
            vgatherqpd(ymm7, ptr[ymm0 + eax], ymm4);
            sdump("C4E2DD933C00");
            vgatherqpd(ymm7, ptr[ymm0 * 4 + ecx], ymm4);
            sdump("C4E2DD933C81");
            vgatherqpd(ymm7, ptr[ymm3 * 8 + edi + 123], ymm4);
            sdump("C4E2DD937CDF7B");
            vgatherqpd(ymm7, ptr[ymm2 * 2 + 5], ymm4);
            sdump("C4E2DD933C5505000000");
            vgatherqpd(ymm7, ptr[eax + ymm0], ymm4);
            sdump("C4E2DD933C00");
            vgatherqpd(ymm7, ptr[esp + ymm2], ymm4);
            sdump("C4E2DD933C14");
        }
    }
}
