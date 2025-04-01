module xed_comp;

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
vcomxsd(xm1, xm2|T_sae);  dump();
vcomxsd(xm1, ptr[rax+128]);  dump();

vcomxsh(xm1, xm2|T_sae);  dump();
vcomxsh(xm1, ptr[rax+128]);  dump();

vcomxss(xm1, xm2|T_sae);  dump();
vcomxss(xm1, ptr[rax+128]);  dump();

vucomxsd(xm1, xm2|T_sae);  dump();
vucomxsd(xm1, ptr[rax+128]);  dump();

vucomxsh(xm1, xm2|T_sae);  dump();
vucomxsh(xm1, ptr[rax+128]);  dump();

vucomxss(xm1, xm2|T_sae);  dump();
vucomxss(xm1, ptr[rax+128]);  dump();

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
                write(format("%02X", p[i * 16 + j]));
            }
        }
        writeln();
        remain -= disp;
        if (remain <= 0) {
            break;
        }
    }
}

@("xed_comp")
unittest
{
    xed_comp();
}

void xed_comp()
{
    //try
    //{
        writeln("comp");
        Code c = new Code();
        auto tbl = c.getCode();
    
        //writeln(c.getSize());    
        //Xdump(tbl, c.getSize());

        writeln("end comp");
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

