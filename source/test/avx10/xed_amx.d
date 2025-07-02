module xed_amx;

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

    @("xed_amx")
    unittest
    {
        xed_amx();
    }

    void xed_amx()
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
            ldtilecfg(ptr[rax + rcx * 4 + 64]);
            sdump("C4E27849448840");
            ldtilecfg(ptr[r30 + r29 * 4 + 0x12]);
            sdump("629A78084944AE12");
            ldtilecfg(ptr[rax]);
            sdump("C4E2784900");
            sttilecfg(ptr[rsp + rax * 8 + 128]);
            sdump("C4E2794984C480000000");
            sttilecfg(ptr[r30 + r29 * 4 + 0x12]);
            sdump("629A79084944AE12");
            sttilecfg(ptr[r30]);
            sdump("62DA7D084906");
            tileloadd(tmm3, ptr[rdi + rdx * 2 + 8]);
            sdump("C4E27B4B5C5708");
            tileloadd(tmm2, ptr[r30 + r29 * 4 + 0x12]);
            sdump("629A7B084B54AE12");
            tileloaddt1(tmm4, ptr[r8 + r9 + 32]);
            sdump("C482794B640820");
            tileloaddt1(tmm7, ptr[r30 + r29 * 4 + 0x12]);
            sdump("629A79084B7CAE12");
            tilerelease();
            sdump("C4E27849C0");
            tilestored(ptr[r10 + r11 * 2 + 32], tmm2);
            sdump("C4827A4B545A20");
            tilestored(ptr[r30 + r29 * 4 + 0x12], tmm1);
            sdump("629A7A084B4CAE12");
            tilezero(tmm7);
            sdump("C4E27B49F8");
            tdpbssd(tmm1, tmm2, tmm3);
            sdump("C4E2635ECA");
            tdpbsud(tmm2, tmm3, tmm4);
            sdump("C4E25A5ED3");
            tdpbusd(tmm3, tmm4, tmm5);
            sdump("C4E2515EDC");
            tdpbuud(tmm4, tmm5, tmm6);
            sdump("C4E2485EE5");
            tdpfp16ps(tmm5, tmm6, tmm7);
            sdump("C4E2435CEE");
            tdpbf16ps(tmm5, tmm6, tmm7);
            sdump("C4E2425CEE");
            tileloadd(tmm1, ptr[r8 + r8]);
            sdump("C4827B4B0C00");
            tileloadd(tmm1, ptr[rax + rcx * 4]);
            sdump("C4E27B4B0C88");
            tileloadd(tmm1, ptr[r8 + r9 * 1 + 0x40]);
            sdump("C4827B4B4C0840");
            tileloadd(tmm1, ptr[r30 + r29 * 1 + 0x80]);
            sdump("629A7B084B8C2E80000000");
            tileloaddrs(tmm3, ptr[rdi + rdx * 2 + 8]);
            sdump("C4E27B4A5C5708");
            tileloaddrs(tmm7, ptr[r31 + rdx * 2 + 8]);
            sdump("62DA7F084A7C5708");
            tileloaddrst1(tmm4, ptr[r8 + r9 + 32]);
            sdump("C482794A640820");
            tileloaddrst1(tmm4, ptr[r25 + r9 + 32]);
            sdump("629A7D084A640920");

            tdpbf8ps(tmm1, tmm2, tmm3);
            sdump("C4E560FDCA");
            tdpbhf8ps(tmm1, tmm2, tmm3);
            sdump("C4E563FDCA");
            tdphbf8ps(tmm1, tmm2, tmm3);
            sdump("C4E562FDCA");
            tdphf8ps(tmm1, tmm2, tmm3);
            sdump("C4E561FDCA");

            tmmultf32ps(tmm1, tmm2, tmm3);
            sdump("C4E26148CA");

            t2rpntlvwz0(tmm1, ptr[rax + r8 * 2 + 0x80]);
            sdump("C4A2786E8C4080000000");
            t2rpntlvwz0(tmm7, ptr[r30 + r8 * 2 + 0x80]);
            sdump("629A7C086EBC4680000000");

            t2rpntlvwz0t1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            sdump("C4A2786F8C4080000000");
            t2rpntlvwz0t1(tmm7, ptr[r30 + r8 * 2 + 0x80]);
            sdump("629A7C086FBC4680000000");

            t2rpntlvwz1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            sdump("C4A2796E8C4080000000");
            t2rpntlvwz1(tmm7, ptr[r30 + r8 * 2 + 0x80]);
            sdump("629A7D086EBC4680000000");

            t2rpntlvwz1t1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            sdump("C4A2796F8C4080000000");
            t2rpntlvwz1t1(tmm7, ptr[r30 + r8 * 2 + 0x80]);
            sdump("629A7D086FBC4680000000");

            t2rpntlvwz0rs(tmm1, ptr[rax + r8 * 2 + 0x80]);
            sdump("C4A578F88C4080000000");
            t2rpntlvwz0rs(tmm7, ptr[r30 + r8 * 2 + 0x80]);
            sdump("629D7C08F8BC4680000000");

            t2rpntlvwz0rst1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            sdump("C4A578F98C4080000000");
            t2rpntlvwz0rst1(tmm7, ptr[r30 + r8 * 2 + 0x80]);
            sdump("629D7C08F9BC4680000000");

            t2rpntlvwz1rs(tmm1, ptr[rax + r8 * 2 + 0x80]);
            sdump("C4A579F88C4080000000");
            t2rpntlvwz1rs(tmm7, ptr[r30 + r8 * 2 + 0x80]);
            sdump("629D7D08F8BC4680000000");

            t2rpntlvwz1rst1(tmm1, ptr[rax + r8 * 2 + 0x80]);
            sdump("C4A579F98C4080000000");
            t2rpntlvwz1rst1(tmm7, ptr[r30 + r8 * 2 + 0x80]);
            sdump("629D7D08F9BC4680000000");

            tcmmimfp16ps(tmm1, tmm2, tmm3);
            sdump("C4E2616CCA");
            tcmmrlfp16ps(tmm1, tmm2, tmm3);
            sdump("C4E2606CCA");

            tconjtcmmimfp16ps(tmm1, tmm2, tmm3);
            sdump("C4E2606BCA");

            tconjtfp16(tmm1, tmm2);
            sdump("C4E2796BCA");

            tcvtrowps2bf16h(zmm1, tmm2, r30d);
            sdump("62F20F406DCA");
            tcvtrowps2bf16h(zmm29, tmm2, 0x12);
            sdump("62637F4807EA12");

            tcvtrowps2bf16l(zmm1, tmm2, r30d);
            sdump("62F20E406DCA");
            tcvtrowps2bf16l(zmm29, tmm2, 0x12);
            sdump("62637E4877EA12");

            tcvtrowps2phh(zmm1, tmm2, r30d);
            sdump("62F20C406DCA");
            tcvtrowps2phh(zmm29, tmm2, 0x12);
            sdump("62637C4807EA12");

            tcvtrowps2phl(zmm1, tmm2, r30d);
            sdump("62F20D406DCA");
            tcvtrowps2phl(zmm29, tmm2, 0x12);
            sdump("62637F4877EA12");

            tilemovrow(zmm1, tmm2, r30d);
            sdump("62F20D404ACA");
            tilemovrow(zmm29, tmm2, 0x12);
            sdump("62637D4807EA12");

            ttcmmimfp16ps(tmm1, tmm2, tmm3);
            sdump("C4E2636BCA");
            ttcmmrlfp16ps(tmm1, tmm2, tmm3);
            sdump("C4E2626BCA");

            ttdpbf16ps(tmm1, tmm2, tmm3);
            sdump("C4E2626CCA");
            ttdpfp16ps(tmm1, tmm2, tmm3);
            sdump("C4E2636CCA");

            ttmmultf32ps(tmm1, tmm2, tmm3);
            sdump("C4E26048CA");

            ttransposed(tmm1, tmm2);
            sdump("C4E27A5FCA");
        }
    }
}
