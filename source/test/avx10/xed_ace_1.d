module xed_ace_1;

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

    @("xed_ace_1")
    unittest
    {
        scope Code c = new Code("xed_ace_1");
    }

    class Code : TestCode
    {
        this(string name)
        {
            super(name); sdump("");
            setDefaultEncodingAVX10(AVX10v2Encoding);

            bsrinit(bsr0); sdump("");

            bsrmovf(bsr0, zmm0, zmm0); sdump("");
            bsrmovf(bsr0, zmm8, zmm8); sdump("");
            bsrmovf(bsr0, zmm16, zmm16); sdump("");
            bsrmovf(bsr0, zmm24, zmm24); sdump("");
            bsrmovf(bsr0, zmm0, zmm24); sdump("");
            bsrmovf(bsr0, zmm8, zmm16); sdump("");
            bsrmovf(bsr0, zmm16, zmm8); sdump("");
            bsrmovf(bsr0, zmm24, zmm0); sdump("");
            bsrmovf(bsr0, zmm0, zword [rax+rcx*1+0x10]); sdump("");
            bsrmovf(bsr0, zmm8, zword [r8+r9*2+0x20]); sdump("");
            bsrmovf(bsr0, zmm16, zword [r16+r17*4+0x40]); sdump("");
            bsrmovf(bsr0, zmm24, zword [r24+r25*8+0x7f]); sdump("");

            bsrmovh(bsr0, zmm0); sdump("");
            bsrmovh(bsr0, zmm8); sdump("");
            bsrmovh(bsr0, zmm16); sdump("");
            bsrmovh(bsr0, zmm24); sdump("");
            bsrmovh(zmm0, bsr0); sdump("");
            bsrmovh(zmm8, bsr0); sdump("");
            bsrmovh(zmm16, bsr0); sdump("");
            bsrmovh(zmm24, bsr0); sdump("");
            bsrmovh(bsr0, zword [rax+rcx*1+0x10]); sdump("");
            bsrmovh(bsr0, zword [r8+r9*2+0x20]); sdump("");
            bsrmovh(bsr0, zword [r16+r17*4+0x40]); sdump("");
            bsrmovh(bsr0, zword [r24+r25*8+0x7f]); sdump("");
            bsrmovh(zword [rax+rcx*1+0x10], bsr0); sdump("");
            bsrmovh(zword [r8+r9*2+0x20], bsr0); sdump("");
            bsrmovh(zword [r16+r17*4+0x40], bsr0); sdump("");
            bsrmovh(zword [r24+r25*8+0x7f], bsr0); sdump("");

            bsrmovl(bsr0, zmm0); sdump("");
            bsrmovl(bsr0, zmm8); sdump("");
            bsrmovl(bsr0, zmm16); sdump("");
            bsrmovl(bsr0, zmm24); sdump("");
            bsrmovl(zmm0, bsr0); sdump("");
            bsrmovl(zmm8, bsr0); sdump("");
            bsrmovl(zmm16, bsr0); sdump("");
            bsrmovl(zmm24, bsr0); sdump("");
            bsrmovl(bsr0, zword [rax+rcx*1+0x08]); sdump("");
            bsrmovl(bsr0, zword [r8+r9*2+0x18]); sdump("");
            bsrmovl(bsr0, zword [r16+r17*4+0x28]); sdump("");
            bsrmovl(bsr0, zword [r24+r25*8+0x38]); sdump("");
            bsrmovl(zword [rax+rcx*1+0x08], bsr0); sdump("");
            bsrmovl(zword [r8+r9*2+0x18], bsr0); sdump("");
            bsrmovl(zword [r16+r17*4+0x28], bsr0); sdump("");
            bsrmovl(zword [r24+r25*8+0x38], bsr0); sdump("");

            tilemovcol(tmm1, zmm0, eax); sdump("");
            tilemovcol(tmm2, zmm8, r8d); sdump("");
            tilemovcol(tmm3, zmm16, r16d); sdump("");
            tilemovcol(tmm4, zmm24, r24d); sdump("");
            tilemovcol(tmm1, zmm0, r24d); sdump("");
            tilemovcol(tmm2, zmm8, r16d); sdump("");
            tilemovcol(tmm3, zmm16, r8d); sdump("");
            tilemovcol(tmm4, zmm24, eax); sdump("");
            tilemovcol(tmm1, zmm0, 0x00); sdump("");
            tilemovcol(tmm2, zmm8, 0x12); sdump("");
            tilemovcol(tmm3, zmm16, 0x2D); sdump("");
            tilemovcol(tmm4, zmm24, 0x3F); sdump("");

            tilemovrow(tmm1, zmm0, eax); sdump("");
            tilemovrow(tmm2, zmm8, r8d); sdump("");
            tilemovrow(tmm3, zmm16, r16d); sdump("");
            tilemovrow(tmm4, zmm24, r24d); sdump("");
            tilemovrow(tmm1, zmm0, r24d); sdump("");
            tilemovrow(tmm2, zmm8, r16d); sdump("");
            tilemovrow(tmm3, zmm16, r8d); sdump("");
            tilemovrow(tmm4, zmm24, eax); sdump("");
            tilemovrow(tmm1, zmm0, 0x00); sdump("");
            tilemovrow(tmm2, zmm8, 0x12); sdump("");
            tilemovrow(tmm3, zmm16, 0x2D); sdump("");
            tilemovrow(tmm4, zmm24, 0x3F); sdump("");

            top2bf16ps(tmm1, zmm0, zmm0); sdump("");
            top2bf16ps(tmm2, zmm8, zmm8); sdump("");
            top2bf16ps(tmm3, zmm16, zmm16); sdump("");
            top2bf16ps(tmm4, zmm24, zmm24); sdump("");
            top2bf16ps(tmm1, zmm0, zmm24); sdump("");
            top2bf16ps(tmm2, zmm8, zmm16); sdump("");
            top2bf16ps(tmm3, zmm16, zmm8); sdump("");
            top2bf16ps(tmm4, zmm24, zmm0); sdump("");

            top4bssd(tmm1, zmm0, zmm0); sdump("");
            top4bssd(tmm2, zmm8, zmm8); sdump("");
            top4bssd(tmm3, zmm16, zmm16); sdump("");
            top4bssd(tmm4, zmm24, zmm24); sdump("");
            top4bssd(tmm1, zmm0, zmm24); sdump("");
            top4bssd(tmm2, zmm8, zmm16); sdump("");
            top4bssd(tmm3, zmm16, zmm8); sdump("");
            top4bssd(tmm4, zmm24, zmm0); sdump("");

            top4bsud(tmm1, zmm0, zmm0); sdump("");
            top4bsud(tmm2, zmm8, zmm8); sdump("");
            top4bsud(tmm3, zmm16, zmm16); sdump("");
            top4bsud(tmm4, zmm24, zmm24); sdump("");
            top4bsud(tmm1, zmm0, zmm24); sdump("");
            top4bsud(tmm2, zmm8, zmm16); sdump("");
            top4bsud(tmm3, zmm16, zmm8); sdump("");
            top4bsud(tmm4, zmm24, zmm0); sdump("");

            top4busd(tmm1, zmm0, zmm0); sdump("");
            top4busd(tmm2, zmm8, zmm8); sdump("");
            top4busd(tmm3, zmm16, zmm16); sdump("");
            top4busd(tmm4, zmm24, zmm24); sdump("");
            top4busd(tmm1, zmm0, zmm24); sdump("");
            top4busd(tmm2, zmm8, zmm16); sdump("");
            top4busd(tmm3, zmm16, zmm8); sdump("");
            top4busd(tmm4, zmm24, zmm0); sdump("");

            top4buud(tmm1, zmm0, zmm0); sdump("");
            top4buud(tmm2, zmm8, zmm8); sdump("");
            top4buud(tmm3, zmm16, zmm16); sdump("");
            top4buud(tmm4, zmm24, zmm24); sdump("");
            top4buud(tmm1, zmm0, zmm24); sdump("");
            top4buud(tmm2, zmm8, zmm16); sdump("");
            top4buud(tmm3, zmm16, zmm8); sdump("");
            top4buud(tmm4, zmm24, zmm0); sdump("");

            top4mxbf8ps(tmm1, zmm0, zmm0, 0x00); sdump("");
            top4mxbf8ps(tmm2, zmm8, zmm8, 0x12); sdump("");
            top4mxbf8ps(tmm3, zmm16, zmm16, 0x2D); sdump("");
            top4mxbf8ps(tmm4, zmm24, zmm24, 0x3F); sdump("");
            top4mxbf8ps(tmm1, zmm0, zmm24, 0x3F); sdump("");
            top4mxbf8ps(tmm2, zmm8, zmm16, 0x2D); sdump("");
            top4mxbf8ps(tmm3, zmm16, zmm8, 0x12); sdump("");
            top4mxbf8ps(tmm4, zmm24, zmm0, 0x00); sdump("");

            top4mxbhf8ps(tmm1, zmm0, zmm0, 0x00); sdump("");
            top4mxbhf8ps(tmm2, zmm8, zmm8, 0x12); sdump("");
            top4mxbhf8ps(tmm3, zmm16, zmm16, 0x2D); sdump("");
            top4mxbhf8ps(tmm4, zmm24, zmm24, 0x3F); sdump("");
            top4mxbhf8ps(tmm1, zmm0, zmm24, 0x3F); sdump("");
            top4mxbhf8ps(tmm2, zmm8, zmm16, 0x2D); sdump("");
            top4mxbhf8ps(tmm3, zmm16, zmm8, 0x12); sdump("");
            top4mxbhf8ps(tmm4, zmm24, zmm0, 0x00); sdump("");

            top4mxhbf8ps(tmm1, zmm0, zmm0, 0x00); sdump("");
            top4mxhbf8ps(tmm2, zmm8, zmm8, 0x12); sdump("");
            top4mxhbf8ps(tmm3, zmm16, zmm16, 0x2D); sdump("");
            top4mxhbf8ps(tmm4, zmm24, zmm24, 0x3F); sdump("");
            top4mxhbf8ps(tmm1, zmm0, zmm24, 0x3F); sdump("");
            top4mxhbf8ps(tmm2, zmm8, zmm16, 0x2D); sdump("");
            top4mxhbf8ps(tmm3, zmm16, zmm8, 0x12); sdump("");
            top4mxhbf8ps(tmm4, zmm24, zmm0, 0x00); sdump("");

            top4mxhf8ps(tmm1, zmm0, zmm0, 0x00); sdump("");
            top4mxhf8ps(tmm2, zmm8, zmm8, 0x12); sdump("");
            top4mxhf8ps(tmm3, zmm16, zmm16, 0x2D); sdump("");
            top4mxhf8ps(tmm4, zmm24, zmm24, 0x3F); sdump("");
            top4mxhf8ps(tmm1, zmm0, zmm24, 0x3F); sdump("");
            top4mxhf8ps(tmm2, zmm8, zmm16, 0x2D); sdump("");
            top4mxhf8ps(tmm3, zmm16, zmm8, 0x12); sdump("");
            top4mxhf8ps(tmm4, zmm24, zmm0, 0x00); sdump("");

            top4mxbssps(tmm1, zmm0, zmm0, 0x00); sdump("");
            top4mxbssps(tmm2, zmm8, zmm8, 0x12); sdump("");
            top4mxbssps(tmm3, zmm16, zmm16, 0x2D); sdump("");
            top4mxbssps(tmm4, zmm24, zmm24, 0x3F); sdump("");
            top4mxbssps(tmm1, zmm0, zmm24, 0x3F); sdump("");
            top4mxbssps(tmm2, zmm8, zmm16, 0x2D); sdump("");
            top4mxbssps(tmm3, zmm16, zmm8, 0x12); sdump("");
            top4mxbssps(tmm4, zmm24, zmm0, 0x00); sdump("");

            // vcvtps2bf8: opCvt5 shape, dst always xm, src grows xm/ym/zm
            vcvtps2bf8(xm0, xm0); sdump("");
            vcvtps2bf8(xm8, xm8); sdump("");
            vcvtps2bf8(xm16, xm16); sdump("");
            vcvtps2bf8(xm24, xm24); sdump("");
            vcvtps2bf8(xm0, xm24); sdump("");
            vcvtps2bf8(xm8, xm16); sdump("");
            vcvtps2bf8(xm16, xm8); sdump("");
            vcvtps2bf8(xm24, xm0); sdump("");
            vcvtps2bf8(xm0, ym0); sdump("");
            vcvtps2bf8(xm8, ym8); sdump("");
            vcvtps2bf8(xm16, ym16); sdump("");
            vcvtps2bf8(xm24, ym24); sdump("");
            vcvtps2bf8(xm0, ym24); sdump("");
            vcvtps2bf8(xm8, ym16); sdump("");
            vcvtps2bf8(xm16, ym8); sdump("");
            vcvtps2bf8(xm24, ym0); sdump("");
            vcvtps2bf8(xm0, zm0); sdump("");
            vcvtps2bf8(xm8, zm8); sdump("");
            vcvtps2bf8(xm16, zm16); sdump("");
            vcvtps2bf8(xm24, zm24); sdump("");
            vcvtps2bf8(xm0, zm24); sdump("");
            vcvtps2bf8(xm8, zm16); sdump("");
            vcvtps2bf8(xm16, zm8); sdump("");
            vcvtps2bf8(xm24, zm0); sdump("");
            vcvtps2bf8(xm0, xword [rax+rcx*1+0x10]); sdump("");
            vcvtps2bf8(xm8, yword [r8+r9*2+0x20]); sdump("");
            vcvtps2bf8(xm16, zword [r16+r17*4+0x40]); sdump("");
            vcvtps2bf8(xm24, zword [r24+r25*8+0x7f]); sdump("");
            vcvtps2bf8(xm0|k4, xm8); sdump("");
            vcvtps2bf8(xm8|k5, xm16); sdump("");
            vcvtps2bf8(xm16|k6, xm24); sdump("");
            vcvtps2bf8(xm24|k7|T_z, xm0); sdump("");
            vcvtps2bf8(xm0|k4, ym8); sdump("");
            vcvtps2bf8(xm8|k5, ym16); sdump("");
            vcvtps2bf8(xm16|k6, ym24); sdump("");
            vcvtps2bf8(xm24|k7|T_z, ym0); sdump("");
            vcvtps2bf8(xm0|k4, zm8); sdump("");
            vcvtps2bf8(xm8|k5, zm16); sdump("");
            vcvtps2bf8(xm16|k6, zm24); sdump("");
            vcvtps2bf8(xm24|k7|T_z, zm0); sdump("");

            // vcvtps2bf8s: opCvt5 shape, dst always xm, src grows xm/ym/zm
            vcvtps2bf8s(xm0, xm0); sdump("");
            vcvtps2bf8s(xm8, xm8); sdump("");
            vcvtps2bf8s(xm16, xm16); sdump("");
            vcvtps2bf8s(xm24, xm24); sdump("");
            vcvtps2bf8s(xm0, xm24); sdump("");
            vcvtps2bf8s(xm8, xm16); sdump("");
            vcvtps2bf8s(xm16, xm8); sdump("");
            vcvtps2bf8s(xm24, xm0); sdump("");
            vcvtps2bf8s(xm0, ym0); sdump("");
            vcvtps2bf8s(xm8, ym8); sdump("");
            vcvtps2bf8s(xm16, ym16); sdump("");
            vcvtps2bf8s(xm24, ym24); sdump("");
            vcvtps2bf8s(xm0, ym24); sdump("");
            vcvtps2bf8s(xm8, ym16); sdump("");
            vcvtps2bf8s(xm16, ym8); sdump("");
            vcvtps2bf8s(xm24, ym0); sdump("");
            vcvtps2bf8s(xm0, zm0); sdump("");
            vcvtps2bf8s(xm8, zm8); sdump("");
            vcvtps2bf8s(xm16, zm16); sdump("");
            vcvtps2bf8s(xm24, zm24); sdump("");
            vcvtps2bf8s(xm0, zm24); sdump("");
            vcvtps2bf8s(xm8, zm16); sdump("");
            vcvtps2bf8s(xm16, zm8); sdump("");
            vcvtps2bf8s(xm24, zm0); sdump("");
            vcvtps2bf8s(xm0, xword [rax+rcx*1+0x10]); sdump("");
            vcvtps2bf8s(xm8, yword [r8+r9*2+0x20]); sdump("");
            vcvtps2bf8s(xm16, zword [r16+r17*4+0x40]); sdump("");
            vcvtps2bf8s(xm24, zword [r24+r25*8+0x7f]); sdump("");
            vcvtps2bf8s(xm0|k4, xm8); sdump("");
            vcvtps2bf8s(xm8|k5, xm16); sdump("");
            vcvtps2bf8s(xm16|k6, xm24); sdump("");
            vcvtps2bf8s(xm24|k7|T_z, xm0); sdump("");
            vcvtps2bf8s(xm0|k4, ym8); sdump("");
            vcvtps2bf8s(xm8|k5, ym16); sdump("");
            vcvtps2bf8s(xm16|k6, ym24); sdump("");
            vcvtps2bf8s(xm24|k7|T_z, ym0); sdump("");
            vcvtps2bf8s(xm0|k4, zm8); sdump("");
            vcvtps2bf8s(xm8|k5, zm16); sdump("");
            vcvtps2bf8s(xm16|k6, zm24); sdump("");
            vcvtps2bf8s(xm24|k7|T_z, zm0); sdump("");

            // vcvtps2hf8: opCvt5 shape, dst always xm, src grows xm/ym/zm
            vcvtps2hf8(xm0, xm0); sdump("");
            vcvtps2hf8(xm8, xm8); sdump("");
            vcvtps2hf8(xm16, xm16); sdump("");
            vcvtps2hf8(xm24, xm24); sdump("");
            vcvtps2hf8(xm0, xm24); sdump("");
            vcvtps2hf8(xm8, xm16); sdump("");
            vcvtps2hf8(xm16, xm8); sdump("");
            vcvtps2hf8(xm24, xm0); sdump("");
            vcvtps2hf8(xm0, ym0); sdump("");
            vcvtps2hf8(xm8, ym8); sdump("");
            vcvtps2hf8(xm16, ym16); sdump("");
            vcvtps2hf8(xm24, ym24); sdump("");
            vcvtps2hf8(xm0, ym24); sdump("");
            vcvtps2hf8(xm8, ym16); sdump("");
            vcvtps2hf8(xm16, ym8); sdump("");
            vcvtps2hf8(xm24, ym0); sdump("");
            vcvtps2hf8(xm0, zm0); sdump("");
            vcvtps2hf8(xm8, zm8); sdump("");
            vcvtps2hf8(xm16, zm16); sdump("");
            vcvtps2hf8(xm24, zm24); sdump("");
            vcvtps2hf8(xm0, zm24); sdump("");
            vcvtps2hf8(xm8, zm16); sdump("");
            vcvtps2hf8(xm16, zm8); sdump("");
            vcvtps2hf8(xm24, zm0); sdump("");
            vcvtps2hf8(xm0, xword [rax+rcx*1+0x10]); sdump("");
            vcvtps2hf8(xm8, yword [r8+r9*2+0x20]); sdump("");
            vcvtps2hf8(xm16, zword [r16+r17*4+0x40]); sdump("");
            vcvtps2hf8(xm24, zword [r24+r25*8+0x7f]); sdump("");
            vcvtps2hf8(xm0|k4, xm8); sdump("");
            vcvtps2hf8(xm8|k5, xm16); sdump("");
            vcvtps2hf8(xm16|k6, xm24); sdump("");
            vcvtps2hf8(xm24|k7|T_z, xm0); sdump("");
            vcvtps2hf8(xm0|k4, ym8); sdump("");
            vcvtps2hf8(xm8|k5, ym16); sdump("");
            vcvtps2hf8(xm16|k6, ym24); sdump("");
            vcvtps2hf8(xm24|k7|T_z, ym0); sdump("");
            vcvtps2hf8(xm0|k4, zm8); sdump("");
            vcvtps2hf8(xm8|k5, zm16); sdump("");
            vcvtps2hf8(xm16|k6, zm24); sdump("");
            vcvtps2hf8(xm24|k7|T_z, zm0); sdump("");

            // vcvtps2hf8s: opCvt5 shape, dst always xm, src grows xm/ym/zm
            vcvtps2hf8s(xm0, xm0); sdump("");
            vcvtps2hf8s(xm8, xm8); sdump("");
            vcvtps2hf8s(xm16, xm16); sdump("");
            vcvtps2hf8s(xm24, xm24); sdump("");
            vcvtps2hf8s(xm0, xm24); sdump("");
            vcvtps2hf8s(xm8, xm16); sdump("");
            vcvtps2hf8s(xm16, xm8); sdump("");
            vcvtps2hf8s(xm24, xm0); sdump("");
            vcvtps2hf8s(xm0, ym0); sdump("");
            vcvtps2hf8s(xm8, ym8); sdump("");
            vcvtps2hf8s(xm16, ym16); sdump("");
            vcvtps2hf8s(xm24, ym24); sdump("");
            vcvtps2hf8s(xm0, ym24); sdump("");
            vcvtps2hf8s(xm8, ym16); sdump("");
            vcvtps2hf8s(xm16, ym8); sdump("");
            vcvtps2hf8s(xm24, ym0); sdump("");
            vcvtps2hf8s(xm0, zm0); sdump("");
            vcvtps2hf8s(xm8, zm8); sdump("");
            vcvtps2hf8s(xm16, zm16); sdump("");
            vcvtps2hf8s(xm24, zm24); sdump("");
            vcvtps2hf8s(xm0, zm24); sdump("");
            vcvtps2hf8s(xm8, zm16); sdump("");
            vcvtps2hf8s(xm16, zm8); sdump("");
            vcvtps2hf8s(xm24, zm0); sdump("");
            vcvtps2hf8s(xm0, xword [rax+rcx*1+0x10]); sdump("");
            vcvtps2hf8s(xm8, yword [r8+r9*2+0x20]); sdump("");
            vcvtps2hf8s(xm16, zword [r16+r17*4+0x40]); sdump("");
            vcvtps2hf8s(xm24, zword [r24+r25*8+0x7f]); sdump("");
            vcvtps2hf8s(xm0|k4, xm8); sdump("");
            vcvtps2hf8s(xm8|k5, xm16); sdump("");
            vcvtps2hf8s(xm16|k6, xm24); sdump("");
            vcvtps2hf8s(xm24|k7|T_z, xm0); sdump("");
            vcvtps2hf8s(xm0|k4, ym8); sdump("");
            vcvtps2hf8s(xm8|k5, ym16); sdump("");
            vcvtps2hf8s(xm16|k6, ym24); sdump("");
            vcvtps2hf8s(xm24|k7|T_z, ym0); sdump("");
            vcvtps2hf8s(xm0|k4, zm8); sdump("");
            vcvtps2hf8s(xm8|k5, zm16); sdump("");
            vcvtps2hf8s(xm16|k6, zm24); sdump("");
            vcvtps2hf8s(xm24|k7|T_z, zm0); sdump("");

            // vcvtrops2hf8: opCvt5 shape, dst always xm, src grows xm/ym/zm
            vcvtrops2hf8(xm0, xm0); sdump("");
            vcvtrops2hf8(xm8, xm8); sdump("");
            vcvtrops2hf8(xm16, xm16); sdump("");
            vcvtrops2hf8(xm24, xm24); sdump("");
            vcvtrops2hf8(xm0, xm24); sdump("");
            vcvtrops2hf8(xm8, xm16); sdump("");
            vcvtrops2hf8(xm16, xm8); sdump("");
            vcvtrops2hf8(xm24, xm0); sdump("");
            vcvtrops2hf8(xm0, ym0); sdump("");
            vcvtrops2hf8(xm8, ym8); sdump("");
            vcvtrops2hf8(xm16, ym16); sdump("");
            vcvtrops2hf8(xm24, ym24); sdump("");
            vcvtrops2hf8(xm0, ym24); sdump("");
            vcvtrops2hf8(xm8, ym16); sdump("");
            vcvtrops2hf8(xm16, ym8); sdump("");
            vcvtrops2hf8(xm24, ym0); sdump("");
            vcvtrops2hf8(xm0, zm0); sdump("");
            vcvtrops2hf8(xm8, zm8); sdump("");
            vcvtrops2hf8(xm16, zm16); sdump("");
            vcvtrops2hf8(xm24, zm24); sdump("");
            vcvtrops2hf8(xm0, zm24); sdump("");
            vcvtrops2hf8(xm8, zm16); sdump("");
            vcvtrops2hf8(xm16, zm8); sdump("");
            vcvtrops2hf8(xm24, zm0); sdump("");
            vcvtrops2hf8(xm0, xword [rax+rcx*1+0x10]); sdump("");
            vcvtrops2hf8(xm8, yword [r8+r9*2+0x20]); sdump("");
            vcvtrops2hf8(xm16, zword [r16+r17*4+0x40]); sdump("");
            vcvtrops2hf8(xm24, zword [r24+r25*8+0x7f]); sdump("");
            vcvtrops2hf8(xm0|k4, xm8); sdump("");
            vcvtrops2hf8(xm8|k5, xm16); sdump("");
            vcvtrops2hf8(xm16|k6, xm24); sdump("");
            vcvtrops2hf8(xm24|k7|T_z, xm0); sdump("");
            vcvtrops2hf8(xm0|k4, ym8); sdump("");
            vcvtrops2hf8(xm8|k5, ym16); sdump("");
            vcvtrops2hf8(xm16|k6, ym24); sdump("");
            vcvtrops2hf8(xm24|k7|T_z, ym0); sdump("");
            vcvtrops2hf8(xm0|k4, zm8); sdump("");
            vcvtrops2hf8(xm8|k5, zm16); sdump("");
            vcvtrops2hf8(xm16|k6, zm24); sdump("");
            vcvtrops2hf8(xm24|k7|T_z, zm0); sdump("");

            // vcvtrops2hf8s: opCvt5 shape, dst always xm, src grows xm/ym/zm
            vcvtrops2hf8s(xm0, xm0); sdump("");
            vcvtrops2hf8s(xm8, xm8); sdump("");
            vcvtrops2hf8s(xm16, xm16); sdump("");
            vcvtrops2hf8s(xm24, xm24); sdump("");
            vcvtrops2hf8s(xm0, xm24); sdump("");
            vcvtrops2hf8s(xm8, xm16); sdump("");
            vcvtrops2hf8s(xm16, xm8); sdump("");
            vcvtrops2hf8s(xm24, xm0); sdump("");
            vcvtrops2hf8s(xm0, ym0); sdump("");
            vcvtrops2hf8s(xm8, ym8); sdump("");
            vcvtrops2hf8s(xm16, ym16); sdump("");
            vcvtrops2hf8s(xm24, ym24); sdump("");
            vcvtrops2hf8s(xm0, ym24); sdump("");
            vcvtrops2hf8s(xm8, ym16); sdump("");
            vcvtrops2hf8s(xm16, ym8); sdump("");
            vcvtrops2hf8s(xm24, ym0); sdump("");
            vcvtrops2hf8s(xm0, zm0); sdump("");
            vcvtrops2hf8s(xm8, zm8); sdump("");
            vcvtrops2hf8s(xm16, zm16); sdump("");
            vcvtrops2hf8s(xm24, zm24); sdump("");
            vcvtrops2hf8s(xm0, zm24); sdump("");
            vcvtrops2hf8s(xm8, zm16); sdump("");
            vcvtrops2hf8s(xm16, zm8); sdump("");
            vcvtrops2hf8s(xm24, zm0); sdump("");
            vcvtrops2hf8s(xm0, xword [rax+rcx*1+0x10]); sdump("");
            vcvtrops2hf8s(xm8, yword [r8+r9*2+0x20]); sdump("");
            vcvtrops2hf8s(xm16, zword [r16+r17*4+0x40]); sdump("");
            vcvtrops2hf8s(xm24, zword [r24+r25*8+0x7f]); sdump("");
            vcvtrops2hf8s(xm0|k4, xm8); sdump("");
            vcvtrops2hf8s(xm8|k5, xm16); sdump("");
            vcvtrops2hf8s(xm16|k6, xm24); sdump("");
            vcvtrops2hf8s(xm24|k7|T_z, xm0); sdump("");
            vcvtrops2hf8s(xm0|k4, ym8); sdump("");
            vcvtrops2hf8s(xm8|k5, ym16); sdump("");
            vcvtrops2hf8s(xm16|k6, ym24); sdump("");
            vcvtrops2hf8s(xm24|k7|T_z, ym0); sdump("");
            vcvtrops2hf8s(xm0|k4, zm8); sdump("");
            vcvtrops2hf8s(xm8|k5, zm16); sdump("");
            vcvtrops2hf8s(xm16|k6, zm24); sdump("");
            vcvtrops2hf8s(xm24|k7|T_z, zm0); sdump("");

            // vcvtbiasps2bf8: dst fixed xm, bias/src grow together xm/ym/zm
            vcvtbiasps2bf8(xm0, xm0, xm0); sdump("");
            vcvtbiasps2bf8(xm8, xm8, xm8); sdump("");
            vcvtbiasps2bf8(xm16, xm16, xm16); sdump("");
            vcvtbiasps2bf8(xm24, xm24, xm24); sdump("");
            vcvtbiasps2bf8(xm0, ym0, ym0); sdump("");
            vcvtbiasps2bf8(xm8, ym8, ym8); sdump("");
            vcvtbiasps2bf8(xm16, ym16, ym16); sdump("");
            vcvtbiasps2bf8(xm24, ym24, ym24); sdump("");
            vcvtbiasps2bf8(xm0, zm0, zm0); sdump("");
            vcvtbiasps2bf8(xm8, zm8, zm8); sdump("");
            vcvtbiasps2bf8(xm16, zm16, zm16); sdump("");
            vcvtbiasps2bf8(xm24, zm24, zm24); sdump("");
            vcvtbiasps2bf8(xm0, xm1, xword [rax+rcx*1+0x10]); sdump("");
            vcvtbiasps2bf8(xm8, ym9, yword [r8+r9*2+0x20]); sdump("");
            vcvtbiasps2bf8(xm16, zm17, zword [r16+r17*4+0x40]); sdump("");
            vcvtbiasps2bf8(xm0|k4, xm8, xm8); sdump("");
            vcvtbiasps2bf8(xm8|k5, xm16, xm16); sdump("");
            vcvtbiasps2bf8(xm16|k6, xm24, xm24); sdump("");
            vcvtbiasps2bf8(xm24|k7|T_z, xm0, xm0); sdump("");
            vcvtbiasps2bf8(xm0|k4, ym8, ym8); sdump("");
            vcvtbiasps2bf8(xm8|k5, ym16, ym16); sdump("");
            vcvtbiasps2bf8(xm16|k6, ym24, ym24); sdump("");
            vcvtbiasps2bf8(xm24|k7|T_z, ym0, ym0); sdump("");
            vcvtbiasps2bf8(xm0|k4, zm8, zm8); sdump("");
            vcvtbiasps2bf8(xm8|k5, zm16, zm16); sdump("");
            vcvtbiasps2bf8(xm16|k6, zm24, zm24); sdump("");
            vcvtbiasps2bf8(xm24|k7|T_z, zm0, zm0); sdump("");

            // vcvtbiasps2bf8s: dst fixed xm, bias/src grow together xm/ym/zm
            vcvtbiasps2bf8s(xm0, xm0, xm0); sdump("");
            vcvtbiasps2bf8s(xm8, xm8, xm8); sdump("");
            vcvtbiasps2bf8s(xm16, xm16, xm16); sdump("");
            vcvtbiasps2bf8s(xm24, xm24, xm24); sdump("");
            vcvtbiasps2bf8s(xm0, ym0, ym0); sdump("");
            vcvtbiasps2bf8s(xm8, ym8, ym8); sdump("");
            vcvtbiasps2bf8s(xm16, ym16, ym16); sdump("");
            vcvtbiasps2bf8s(xm24, ym24, ym24); sdump("");
            vcvtbiasps2bf8s(xm0, zm0, zm0); sdump("");
            vcvtbiasps2bf8s(xm8, zm8, zm8); sdump("");
            vcvtbiasps2bf8s(xm16, zm16, zm16); sdump("");
            vcvtbiasps2bf8s(xm24, zm24, zm24); sdump("");
            vcvtbiasps2bf8s(xm0, xm1, xword [rax+rcx*1+0x10]); sdump("");
            vcvtbiasps2bf8s(xm8, ym9, yword [r8+r9*2+0x20]); sdump("");
            vcvtbiasps2bf8s(xm16, zm17, zword [r16+r17*4+0x40]); sdump("");
            vcvtbiasps2bf8s(xm0|k4, xm8, xm8); sdump("");
            vcvtbiasps2bf8s(xm8|k5, xm16, xm16); sdump("");
            vcvtbiasps2bf8s(xm16|k6, xm24, xm24); sdump("");
            vcvtbiasps2bf8s(xm24|k7|T_z, xm0, xm0); sdump("");
            vcvtbiasps2bf8s(xm0|k4, ym8, ym8); sdump("");
            vcvtbiasps2bf8s(xm8|k5, ym16, ym16); sdump("");
            vcvtbiasps2bf8s(xm16|k6, ym24, ym24); sdump("");
            vcvtbiasps2bf8s(xm24|k7|T_z, ym0, ym0); sdump("");
            vcvtbiasps2bf8s(xm0|k4, zm8, zm8); sdump("");
            vcvtbiasps2bf8s(xm8|k5, zm16, zm16); sdump("");
            vcvtbiasps2bf8s(xm16|k6, zm24, zm24); sdump("");
            vcvtbiasps2bf8s(xm24|k7|T_z, zm0, zm0); sdump("");

            // vcvtbiasps2hf8: dst fixed xm, bias/src grow together xm/ym/zm
            vcvtbiasps2hf8(xm0, xm0, xm0); sdump("");
            vcvtbiasps2hf8(xm8, xm8, xm8); sdump("");
            vcvtbiasps2hf8(xm16, xm16, xm16); sdump("");
            vcvtbiasps2hf8(xm24, xm24, xm24); sdump("");
            vcvtbiasps2hf8(xm0, ym0, ym0); sdump("");
            vcvtbiasps2hf8(xm8, ym8, ym8); sdump("");
            vcvtbiasps2hf8(xm16, ym16, ym16); sdump("");
            vcvtbiasps2hf8(xm24, ym24, ym24); sdump("");
            vcvtbiasps2hf8(xm0, zm0, zm0); sdump("");
            vcvtbiasps2hf8(xm8, zm8, zm8); sdump("");
            vcvtbiasps2hf8(xm16, zm16, zm16); sdump("");
            vcvtbiasps2hf8(xm24, zm24, zm24); sdump("");
            vcvtbiasps2hf8(xm0, xm1, xword [rax+rcx*1+0x10]); sdump("");
            vcvtbiasps2hf8(xm8, ym9, yword [r8+r9*2+0x20]); sdump("");
            vcvtbiasps2hf8(xm16, zm17, zword [r16+r17*4+0x40]); sdump("");
            vcvtbiasps2hf8(xm0|k4, xm8, xm8); sdump("");
            vcvtbiasps2hf8(xm8|k5, xm16, xm16); sdump("");
            vcvtbiasps2hf8(xm16|k6, xm24, xm24); sdump("");
            vcvtbiasps2hf8(xm24|k7|T_z, xm0, xm0); sdump("");
            vcvtbiasps2hf8(xm0|k4, ym8, ym8); sdump("");
            vcvtbiasps2hf8(xm8|k5, ym16, ym16); sdump("");
            vcvtbiasps2hf8(xm16|k6, ym24, ym24); sdump("");
            vcvtbiasps2hf8(xm24|k7|T_z, ym0, ym0); sdump("");
            vcvtbiasps2hf8(xm0|k4, zm8, zm8); sdump("");
            vcvtbiasps2hf8(xm8|k5, zm16, zm16); sdump("");
            vcvtbiasps2hf8(xm16|k6, zm24, zm24); sdump("");
            vcvtbiasps2hf8(xm24|k7|T_z, zm0, zm0); sdump("");

            // vcvtbiasps2hf8s: dst fixed xm, bias/src grow together xm/ym/zm
            vcvtbiasps2hf8s(xm0, xm0, xm0); sdump("");
            vcvtbiasps2hf8s(xm8, xm8, xm8); sdump("");
            vcvtbiasps2hf8s(xm16, xm16, xm16); sdump("");
            vcvtbiasps2hf8s(xm24, xm24, xm24); sdump("");
            vcvtbiasps2hf8s(xm0, ym0, ym0); sdump("");
            vcvtbiasps2hf8s(xm8, ym8, ym8); sdump("");
            vcvtbiasps2hf8s(xm16, ym16, ym16); sdump("");
            vcvtbiasps2hf8s(xm24, ym24, ym24); sdump("");
            vcvtbiasps2hf8s(xm0, zm0, zm0); sdump("");
            vcvtbiasps2hf8s(xm8, zm8, zm8); sdump("");
            vcvtbiasps2hf8s(xm16, zm16, zm16); sdump("");
            vcvtbiasps2hf8s(xm24, zm24, zm24); sdump("");
            vcvtbiasps2hf8s(xm0, xm1, xword [rax+rcx*1+0x10]); sdump("");
            vcvtbiasps2hf8s(xm8, ym9, yword [r8+r9*2+0x20]); sdump("");
            vcvtbiasps2hf8s(xm16, zm17, zword [r16+r17*4+0x40]); sdump("");
            vcvtbiasps2hf8s(xm0|k4, xm8, xm8); sdump("");
            vcvtbiasps2hf8s(xm8|k5, xm16, xm16); sdump("");
            vcvtbiasps2hf8s(xm16|k6, xm24, xm24); sdump("");
            vcvtbiasps2hf8s(xm24|k7|T_z, xm0, xm0); sdump("");
            vcvtbiasps2hf8s(xm0|k4, ym8, ym8); sdump("");
            vcvtbiasps2hf8s(xm8|k5, ym16, ym16); sdump("");
            vcvtbiasps2hf8s(xm16|k6, ym24, ym24); sdump("");
            vcvtbiasps2hf8s(xm24|k7|T_z, ym0, ym0); sdump("");
            vcvtbiasps2hf8s(xm0|k4, zm8, zm8); sdump("");
            vcvtbiasps2hf8s(xm8|k5, zm16, zm16); sdump("");
            vcvtbiasps2hf8s(xm16|k6, zm24, zm24); sdump("");
            vcvtbiasps2hf8s(xm24|k7|T_z, zm0, zm0); sdump("");

            // vcvtbf82ps: dst grows xm/ym/zm, register-form src fixed xm
            vcvtbf82ps(xm0, xm24); sdump("");
            vcvtbf82ps(xm8, xm0); sdump("");
            vcvtbf82ps(xm16, xm8); sdump("");
            vcvtbf82ps(xm24, xm0); sdump("");
            vcvtbf82ps(ym0, xm8); sdump("");
            vcvtbf82ps(ym8, xm16); sdump("");
            vcvtbf82ps(ym16, xm24); sdump("");
            vcvtbf82ps(ym24, xm0); sdump("");
            vcvtbf82ps(zm0, xm16); sdump("");
            vcvtbf82ps(zm8, xm24); sdump("");
            vcvtbf82ps(zm16, xm0); sdump("");
            vcvtbf82ps(zm24, xm8); sdump("");
            vcvtbf82ps(xm0, dword [rax+rcx*1+0x10]); sdump("");
            vcvtbf82ps(ym8, qword [r8+r9*2+0x20]); sdump("");
            vcvtbf82ps(zm16, xword [r16+r17*4+0x40]); sdump("");
            vcvtbf82ps(xm0|k4, xm8); sdump("");
            vcvtbf82ps(ym8|k5, xm16); sdump("");
            vcvtbf82ps(zm16|k6|T_z, xm24); sdump("");
            vcvtbf82ps(zm24|k7, xm8); sdump("");

            // vcvthf82ps: dst grows xm/ym/zm, register-form src fixed xm
            vcvthf82ps(xm0, xm24); sdump("");
            vcvthf82ps(xm8, xm0); sdump("");
            vcvthf82ps(xm16, xm8); sdump("");
            vcvthf82ps(xm24, xm0); sdump("");
            vcvthf82ps(ym0, xm8); sdump("");
            vcvthf82ps(ym8, xm16); sdump("");
            vcvthf82ps(ym16, xm24); sdump("");
            vcvthf82ps(ym24, xm0); sdump("");
            vcvthf82ps(zm0, xm16); sdump("");
            vcvthf82ps(zm8, xm24); sdump("");
            vcvthf82ps(zm16, xm0); sdump("");
            vcvthf82ps(zm24, xm8); sdump("");
            vcvthf82ps(xm0, dword [rax+rcx*1+0x10]); sdump("");
            vcvthf82ps(ym8, qword [r8+r9*2+0x20]); sdump("");
            vcvthf82ps(zm16, xword [r16+r17*4+0x40]); sdump("");
            vcvthf82ps(xm0|k4, xm8); sdump("");
            vcvthf82ps(ym8|k5, xm16); sdump("");
            vcvthf82ps(zm16|k6|T_z, xm24); sdump("");
            vcvthf82ps(zm24|k7, xm8); sdump("");

            // vcvtbf42hf8: dst grows xm/ym/zm; register src is xm at 128/256, ym at 512
            vcvtbf42hf8(xm0, xm24); sdump("");
            vcvtbf42hf8(xm8, xm0); sdump("");
            vcvtbf42hf8(xm16, xm8); sdump("");
            vcvtbf42hf8(xm24, xm0); sdump("");
            vcvtbf42hf8(ym0, xm8); sdump("");
            vcvtbf42hf8(ym8, xm16); sdump("");
            vcvtbf42hf8(ym16, xm24); sdump("");
            vcvtbf42hf8(ym24, xm0); sdump("");
            vcvtbf42hf8(zm0, ym16); sdump("");
            vcvtbf42hf8(zm8, ym24); sdump("");
            vcvtbf42hf8(zm16, ym0); sdump("");
            vcvtbf42hf8(zm24, ym8); sdump("");
            vcvtbf42hf8(xm0, qword [rax+rcx*1+0x10]); sdump("");
            vcvtbf42hf8(ym8, xword [r8+r9*2+0x20]); sdump("");
            vcvtbf42hf8(zm16, yword [r16+r17*4+0x40]); sdump("");
            vcvtbf42hf8(xm0|k4, xm8); sdump("");
            vcvtbf42hf8(ym8|k5, xm16); sdump("");
            vcvtbf42hf8(zm16|k6|T_z, ym24); sdump("");
            vcvtbf42hf8(zm24|k7, ym0); sdump("");

            // vcvtbf62hf8: same-VL reinterpret convert, register-only, masking-eligible
            vcvtbf62hf8(xm0, xm0); sdump("");
            vcvtbf62hf8(xm8, xm8); sdump("");
            vcvtbf62hf8(xm16, xm16); sdump("");
            vcvtbf62hf8(xm24, xm24); sdump("");
            vcvtbf62hf8(ym0, ym0); sdump("");
            vcvtbf62hf8(ym8, ym8); sdump("");
            vcvtbf62hf8(ym16, ym16); sdump("");
            vcvtbf62hf8(ym24, ym24); sdump("");
            vcvtbf62hf8(zm0, zm0); sdump("");
            vcvtbf62hf8(zm8, zm8); sdump("");
            vcvtbf62hf8(zm16, zm16); sdump("");
            vcvtbf62hf8(zm24, zm24); sdump("");
            vcvtbf62hf8(xm0|k4, xm8); sdump("");
            vcvtbf62hf8(ym8|k5, ym16); sdump("");
            vcvtbf62hf8(zm16|k6|T_z, zm24); sdump("");
            vcvtbf62hf8(zm24|k7, zm16); sdump("");

            // vcvthf62hf8: same-VL reinterpret convert, register-only, masking-eligible
            vcvthf62hf8(xm0, xm0); sdump("");
            vcvthf62hf8(xm8, xm8); sdump("");
            vcvthf62hf8(xm16, xm16); sdump("");
            vcvthf62hf8(xm24, xm24); sdump("");
            vcvthf62hf8(ym0, ym0); sdump("");
            vcvthf62hf8(ym8, ym8); sdump("");
            vcvthf62hf8(ym16, ym16); sdump("");
            vcvthf62hf8(ym24, ym24); sdump("");
            vcvthf62hf8(zm0, zm0); sdump("");
            vcvthf62hf8(zm8, zm8); sdump("");
            vcvthf62hf8(zm16, zm16); sdump("");
            vcvthf62hf8(zm24, zm24); sdump("");
            vcvthf62hf8(xm0|k4, xm8); sdump("");
            vcvthf62hf8(ym8|k5, ym16); sdump("");
            vcvthf62hf8(zm16|k6|T_z, zm24); sdump("");
            vcvthf62hf8(zm24|k7, zm16); sdump("");

            // vcvtbf82bf6s: same-VL narrowing convert, register-only, no masking form in spec table
            vcvtbf82bf6s(xm0, xm0); sdump("");
            vcvtbf82bf6s(xm8, xm8); sdump("");
            vcvtbf82bf6s(xm16, xm16); sdump("");
            vcvtbf82bf6s(xm24, xm24); sdump("");
            vcvtbf82bf6s(ym0, ym0); sdump("");
            vcvtbf82bf6s(ym8, ym8); sdump("");
            vcvtbf82bf6s(ym16, ym16); sdump("");
            vcvtbf82bf6s(ym24, ym24); sdump("");
            vcvtbf82bf6s(zm0, zm0); sdump("");
            vcvtbf82bf6s(zm8, zm8); sdump("");
            vcvtbf82bf6s(zm16, zm16); sdump("");
            vcvtbf82bf6s(zm24, zm24); sdump("");

            // vcvthf82hf6s: same-VL narrowing convert, register-only, no masking form in spec table
            vcvthf82hf6s(xm0, xm0); sdump("");
            vcvthf82hf6s(xm8, xm8); sdump("");
            vcvthf82hf6s(xm16, xm16); sdump("");
            vcvthf82hf6s(xm24, xm24); sdump("");
            vcvthf82hf6s(ym0, ym0); sdump("");
            vcvthf82hf6s(ym8, ym8); sdump("");
            vcvthf82hf6s(ym16, ym16); sdump("");
            vcvthf82hf6s(ym24, ym24); sdump("");
            vcvthf82hf6s(zm0, zm0); sdump("");
            vcvthf82hf6s(zm8, zm8); sdump("");
            vcvthf82hf6s(zm16, zm16); sdump("");
            vcvthf82hf6s(zm24, zm24); sdump("");

            // vcvtbf82bf4s: narrow-store, dst(mem-or-narrower-reg)/src(wider-reg) grow together
            vcvtbf82bf4s(xm0, xm24); sdump("");
            vcvtbf82bf4s(xm8, xm0); sdump("");
            vcvtbf82bf4s(xm16, xm8); sdump("");
            vcvtbf82bf4s(xm24, xm0); sdump("");
            vcvtbf82bf4s(xm0, ym8); sdump("");
            vcvtbf82bf4s(xm8, ym16); sdump("");
            vcvtbf82bf4s(xm16, ym24); sdump("");
            vcvtbf82bf4s(xm24, ym0); sdump("");
            vcvtbf82bf4s(ym0, zm16); sdump("");
            vcvtbf82bf4s(ym8, zm24); sdump("");
            vcvtbf82bf4s(ym16, zm0); sdump("");
            vcvtbf82bf4s(ym24, zm8); sdump("");
            vcvtbf82bf4s(qword [rax+rcx*1+0x10], xm0); sdump("");
            vcvtbf82bf4s(xword [r8+r9*2+0x20], ym8); sdump("");
            vcvtbf82bf4s(yword [r16+r17*4+0x40], zm16); sdump("");

            // vcvthf82bf4s: narrow-store, dst(mem-or-narrower-reg)/src(wider-reg) grow together
            vcvthf82bf4s(xm0, xm24); sdump("");
            vcvthf82bf4s(xm8, xm0); sdump("");
            vcvthf82bf4s(xm16, xm8); sdump("");
            vcvthf82bf4s(xm24, xm0); sdump("");
            vcvthf82bf4s(xm0, ym8); sdump("");
            vcvthf82bf4s(xm8, ym16); sdump("");
            vcvthf82bf4s(xm16, ym24); sdump("");
            vcvthf82bf4s(xm24, ym0); sdump("");
            vcvthf82bf4s(ym0, zm16); sdump("");
            vcvthf82bf4s(ym8, zm24); sdump("");
            vcvthf82bf4s(ym16, zm0); sdump("");
            vcvthf82bf4s(ym24, zm8); sdump("");
            vcvthf82bf4s(qword [rax+rcx*1+0x10], xm0); sdump("");
            vcvthf82bf4s(xword [r8+r9*2+0x20], ym8); sdump("");
            vcvthf82bf4s(yword [r16+r17*4+0x40], zm16); sdump("");

            // vunpackb: opAVX_X_XM_IMM shape, masking-eligible, all VLs
            vunpackb(xm0, xm24, 0x00); sdump("");
            vunpackb(xm8, xm0, 0x08); sdump("");
            vunpackb(xm16, xm8, 0x10); sdump("");
            vunpackb(xm24, xm0, 0x18); sdump("");
            vunpackb(ym0, ym8, 0x00); sdump("");
            vunpackb(ym8, ym16, 0x08); sdump("");
            vunpackb(ym16, ym24, 0x10); sdump("");
            vunpackb(ym24, ym0, 0x18); sdump("");
            vunpackb(zm0, zm16, 0x00); sdump("");
            vunpackb(zm8, zm24, 0x08); sdump("");
            vunpackb(zm16, zm0, 0x10); sdump("");
            vunpackb(zm24, zm8, 0x18); sdump("");
            vunpackb(xm0, xword [rax+rcx*1+0x10], 0x11); sdump("");
            vunpackb(ym8, yword [r8+r9*2+0x20], 0x22); sdump("");
            vunpackb(zm16, zword [r16+r17*4+0x40], 0x33); sdump("");
            vunpackb(xm0|k4, xm8, 0x01); sdump("");
            vunpackb(ym8|k5, ym16, 0x02); sdump("");
            vunpackb(zm16|k6|T_z, zm24, 0x03); sdump("");
            vunpackb(zm24|k7, zm8, 0x04); sdump("");

            // vpmovssdb: narrow-store, dst register form fixed xm, src grows xm/ym/zm
            vpmovssdb(xm0, xm24); sdump("");
            vpmovssdb(xm8, xm0); sdump("");
            vpmovssdb(xm16, xm8); sdump("");
            vpmovssdb(xm24, xm0); sdump("");
            vpmovssdb(xm0, ym8); sdump("");
            vpmovssdb(xm8, ym16); sdump("");
            vpmovssdb(xm16, ym24); sdump("");
            vpmovssdb(xm24, ym0); sdump("");
            vpmovssdb(xm0, zm16); sdump("");
            vpmovssdb(xm8, zm24); sdump("");
            vpmovssdb(xm16, zm0); sdump("");
            vpmovssdb(xm24, zm8); sdump("");
            vpmovssdb(dword [rax+rcx*1+0x10], xm0); sdump("");
            vpmovssdb(qword [r8+r9*2+0x20], ym8); sdump("");
            vpmovssdb(xword [r16+r17*4+0x40], zm16); sdump("");
            vpmovssdb(dword [rax+rcx*1+0x10]|k4, xm0); sdump("");
            vpmovssdb(xword [r16+r17*4+0x40]|k5, zm16); sdump("");
        }
    }
}
