module xed_comp;

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

    @("xed_comp")
    unittest
    {
        xed_comp();
    }

    void xed_comp()
    {
        writeln("xed_comp");
        scope Code c = new Code();
    }

    class Code : CodeGenerator
    {
        this()
        {
            super(4096 * 8);
            setDefaultEncodingAVX10(AVX10v2Encoding);
            vcomxsd(xm1, xm2 | T_sae);
            vcomxsd(xm1, ptr[rax + 128]);

            vcomxsh(xm1, xm2 | T_sae);
            vcomxsh(xm1, ptr[rax + 128]);

            vcomxss(xm1, xm2 | T_sae);
            vcomxss(xm1, ptr[rax + 128]);

            vucomxsd(xm1, xm2 | T_sae);
            vucomxsd(xm1, ptr[rax + 128]);

            vucomxsh(xm1, xm2 | T_sae);
            vucomxsh(xm1, ptr[rax + 128]);

            vucomxss(xm1, xm2 | T_sae);
            vucomxss(xm1, ptr[rax + 128]);
        }
    }
}
