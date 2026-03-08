module xed_comp;

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

    @("xed_comp")
    unittest
    {
        scope Code c = new Code("xed_comp");
    }

    class Code : TestCode
    {
        this(string name)
        {
            super(name);
            setDefaultEncodingAVX10(AVX10v2Encoding);

            vcomxsd(xm1, xm2 | T_sae);
            sdump("62F1FF182FCA");
            vcomxsd(xm1, ptr[rax + 128]);
            sdump("62F1FF082F4810");

            vcomxsh(xm1, xm2 | T_sae);
            sdump("62F57E182FCA");
            vcomxsh(xm1, ptr[rax + 128]);
            sdump("62F57E082F4840");

            vcomxss(xm1, xm2 | T_sae);
            sdump("62F17E182FCA");
            vcomxss(xm1, ptr[rax + 128]);
            sdump("62F17E082F4820");

            vucomxsd(xm1, xm2 | T_sae);
            sdump("62F1FF182ECA");
            vucomxsd(xm1, ptr[rax + 128]);
            sdump("62F1FF082E4810");

            vucomxsh(xm1, xm2 | T_sae);
            sdump("62F57E182ECA");
            vucomxsh(xm1, ptr[rax + 128]);
            sdump("62F57E082E4840");

            vucomxss(xm1, xm2 | T_sae);
            sdump("62F17E182ECA");
            vucomxss(xm1, ptr[rax + 128]);
            sdump("62F17E082E4820");

        }
    }
}
