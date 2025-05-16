module xed_apx;

import std.stdio;
import std.string;
import std.algorithm;
import std.stdint;
import std.exception;
import xbyak;


class Code : CodeGenerator
{
    this()
    {
        super(4096*8);
        setDefaultEncodingAVX10(AVX10v2Encoding);

        sal(rax, r8,   1); dump(); size_ = 0;
        sar(rax, r9,   4); dump(); size_ = 0;
        shl(rax, rdi,  8); dump(); size_ = 0;
        shr(rax, rsi, 12); dump(); size_ = 0;
        rcl(rax, r10, 16); dump(); size_ = 0;
        rcr(rax, r11, 20); dump(); size_ = 0;
        rol(rax, r14, 24); dump(); size_ = 0;
        ror(rax, r15, 28); dump(); size_ = 0;
        sal(rcx, qword[r8],  32); dump(); size_ = 0;
        sar(rcx, qword[r9],  36); dump(); size_ = 0;
        sal(rcx, qword[rdi], 40); dump(); size_ = 0;
        sar(rcx, qword[rsi], 44); dump(); size_ = 0;
        rcl(rcx, qword[r10], 48); dump(); size_ = 0;
        rcr(rcx, qword[r11], 52); dump(); size_ = 0;
        rol(rcx, qword[r14], 56); dump(); size_ = 0;
        ror(rcx, qword[r15], 60); dump(); size_ = 0;

        imul(rax, rdx, r10); dump(); size_ = 0;
        imul(rcx, r15, qword[rdi]); dump(); size_ = 0;
    }
}

void Xdump(uint8_t* p, size_t bufSize) 
{
    size_t remain  = bufSize;
    for (int i = 0; i < 4; i++) {
        size_t disp = 16;
        if (remain < 16) {
            disp = remain;
        }
        for (size_t j = 0; j < 16; j++) {
            if (j < disp) {
    //            write(format("%02X", p[i * 16 + j]));
            }
        }
        writeln();
        remain -= disp;
        if (remain <= 0) {
            break;
        }
    }
}

@("xed_apx")
unittest
{
    xed_apx();
}

void xed_apx()
{
    //try
    //{
    //    writeln("xed_apx");
        Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

//        writeln("end xed_apx");
    //    FILE *fp = fopen("bin", "wb");
    //    if (fp) {
    //        fwrite(c.getCode(), 1, c.getSize(), fp);
    //        fclose(fp);
    //} 
    //catch (Exception e)
    //{
    //    printf("ERR %s\n", e.what());
    //}
}

