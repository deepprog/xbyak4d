module test.address;

version = XBYAK64;
unittest
{
    import std.stdio;
    import std.string;
    import std.exception;
    import xbyak4d;


    void a()
    {
        asm
        {
            naked;
            mov ECX, int ptr[EAX + EAX + 0];
        }
    }

    class Code : CodeGenerator
    {
        this()
        {
            mov(ecx, ptr[eax + eax + 0]);
            mov(ecx, ptr[eax + eax + 1]);
            mov(ecx, ptr[eax + eax + 1000]);
            mov(ecx, ptr[eax + eax - 1]);
            mov(ecx, ptr[eax + eax - 1000]);
            mov(ecx, ptr[eax + eax * 1 + 0]);
            mov(ecx, ptr[eax + eax * 1 + 1]);
	        mov(ecx, ptr[eax + eax * 1 + 1000]);
            mov(ecx, ptr[eax + eax * 1 - 1]);
            mov(ecx, ptr[eax + eax * 1 - 1000]);
            mov(ecx, ptr[eax + eax * 2 + 0]);
            mov(ecx, ptr[eax + eax * 2 + 1]);
            mov(ecx, ptr[eax + eax * 2 + 1000]);
            mov(ecx, ptr[eax + eax * 2 - 1]);
            mov(ecx, ptr[eax + eax * 2 - 1000]);
            mov(ecx, ptr[eax + eax * 4 + 0]);
            mov(ecx, ptr[eax + eax * 4 + 1]);
            mov(ecx, ptr[eax + eax * 4 + 1000]);
            mov(ecx, ptr[eax + eax * 4 - 1]);
            mov(ecx, ptr[eax + eax * 4 - 1000]);
            mov(ecx, ptr[eax + eax * 8 + 0]);
            mov(ecx, ptr[eax + eax * 8 + 1]);
            mov(ecx, ptr[eax + eax * 8 + 1000]);
            mov(ecx, ptr[eax + eax * 8 - 1]);
            mov(ecx, ptr[eax + eax * 8 - 1000]);
            mov(ecx, ptr[eax + ecx + 0]);
            mov(ecx, ptr[eax + ecx + 1]);
            mov(ecx, ptr[eax + ecx + 1000]);
            mov(ecx, ptr[eax + ecx - 1]);
            mov(ecx, ptr[eax + ecx - 1000]);
            mov(ecx, ptr[eax + ecx * 1 + 0]);
            mov(ecx, ptr[eax + ecx * 1 + 1]);
            mov(ecx, ptr[eax + ecx * 1 + 1000]);
            mov(ecx, ptr[eax + ecx * 1 - 1]);
            mov(ecx, ptr[eax + ecx * 1 - 1000]);
            mov(ecx, ptr[eax + ecx * 2 + 0]);
            mov(ecx, ptr[eax + ecx * 2 + 1]);
            mov(ecx, ptr[eax + ecx * 2 + 1000]);
            mov(ecx, ptr[eax + ecx * 2 - 1]);
            mov(ecx, ptr[eax + ecx * 2 - 1000]);
            mov(ecx, ptr[eax + ecx * 4 + 0]);
            mov(ecx, ptr[eax + ecx * 4 + 1]);
            mov(ecx, ptr[eax + ecx * 4 + 1000]);
            mov(ecx, ptr[eax + ecx * 4 - 1]);
            mov(ecx, ptr[eax + ecx * 4 - 1000]);
            mov(ecx, ptr[eax + ecx * 8 + 0]);
            mov(ecx, ptr[eax + ecx * 8 + 1]);
            mov(ecx, ptr[eax + ecx * 8 + 1000]);
            mov(ecx, ptr[eax + ecx * 8 - 1]);
            mov(ecx, ptr[eax + ecx * 8 - 1000]);
            mov(ecx, ptr[eax + edx + 0]);
            mov(ecx, ptr[eax + edx + 1]);
            mov(ecx, ptr[eax + edx + 1000]);
            mov(ecx, ptr[eax + edx - 1]);
            mov(ecx, ptr[eax + edx - 1000]);
            mov(ecx, ptr[eax + edx * 1 + 0]);
            mov(ecx, ptr[eax + edx * 1 + 1]);
            mov(ecx, ptr[eax + edx * 1 + 1000]);
            mov(ecx, ptr[eax + edx * 1 - 1]);
            mov(ecx, ptr[eax + edx * 1 - 1000]);
            mov(ecx, ptr[eax + edx * 2 + 0]);
            mov(ecx, ptr[eax + edx * 2 + 1]);
            mov(ecx, ptr[eax + edx * 2 + 1000]);
            mov(ecx, ptr[eax + edx * 2 - 1]);
            mov(ecx, ptr[eax + edx * 2 - 1000]);
            mov(ecx, ptr[eax + edx * 4 + 0]);
            mov(ecx, ptr[eax + edx * 4 + 1]);
            mov(ecx, ptr[eax + edx * 4 + 1000]);
            mov(ecx, ptr[eax + edx * 4 - 1]);
            mov(ecx, ptr[eax + edx * 4 - 1000]);
            mov(ecx, ptr[eax + edx * 8 + 0]);
            mov(ecx, ptr[eax + edx * 8 + 1]);
            mov(ecx, ptr[eax + edx * 8 + 1000]);
            mov(ecx, ptr[eax + edx * 8 - 1]);
            mov(ecx, ptr[eax + edx * 8 - 1000]);
            mov(ecx, ptr[eax + ebx + 0]);
            mov(ecx, ptr[eax + ebx + 1]);
            mov(ecx, ptr[eax + ebx + 1000]);
            mov(ecx, ptr[eax + ebx - 1]);
            mov(ecx, ptr[eax + ebx - 1000]);
            mov(ecx, ptr[eax + ebx * 1 + 0]);
            mov(ecx, ptr[eax + ebx * 1 + 1]);
            mov(ecx, ptr[eax + ebx * 1 + 1000]);
            mov(ecx, ptr[eax + ebx * 1 - 1]);
            mov(ecx, ptr[eax + ebx * 1 - 1000]);
            mov(ecx, ptr[eax + ebx * 2 + 0]);
            mov(ecx, ptr[eax + ebx * 2 + 1]);
            mov(ecx, ptr[eax + ebx * 2 + 1000]);
            mov(ecx, ptr[eax + ebx * 2 - 1]);
            mov(ecx, ptr[eax + ebx * 2 - 1000]);
            mov(ecx, ptr[eax + ebx * 4 + 0]);
            mov(ecx, ptr[eax + ebx * 4 + 1]);
            mov(ecx, ptr[eax + ebx * 4 + 1000]);
            mov(ecx, ptr[eax + ebx * 4 - 1]);
            mov(ecx, ptr[eax + ebx * 4 - 1000]);
            mov(ecx, ptr[eax + ebx * 8 + 0]);
            mov(ecx, ptr[eax + ebx * 8 + 1]);
            mov(ecx, ptr[eax + ebx * 8 + 1000]);
            mov(ecx, ptr[eax + ebx * 8 - 1]);
            mov(ecx, ptr[eax + ebx * 8 - 1000]);

            version(XBYAK64)
            {
                vgatherdpd(ymm7, ptr[xmm0], ymm4);
                vgatherdpd(ymm7, ptr[xmm0 * 1], ymm4);
                vgatherdpd(ymm7, ptr[xmm0 + 4], ymm4);
                vgatherdpd(ymm7, ptr[xmm0 + eax], ymm4);
                vgatherdpd(ymm7, ptr[xmm0 * 4 + ecx], ymm4);
                vgatherdpd(ymm7, ptr[xmm3 * 8 + edi + 123], ymm4);
                vgatherdpd(ymm7, ptr[xmm2 * 2 + 5], ymm4);
                vgatherdpd(ymm7, ptr[eax + xmm0], ymm4);
                vgatherdpd(ymm7, ptr[esp + xmm4], ymm4);

                vgatherqpd(ymm7, ptr[ymm0], ymm4);
                vgatherqpd(ymm7, ptr[ymm0 * 1], ymm4);
                vgatherqpd(ymm7, ptr[ymm0 + 4], ymm4);
                vgatherqpd(ymm7, ptr[ymm0 + eax], ymm4);
                vgatherqpd(ymm7, ptr[ymm0 * 4 + ecx], ymm4);
                vgatherqpd(ymm7, ptr[ymm3 * 8 + edi + 123], ymm4);
                vgatherqpd(ymm7, ptr[ymm2 * 2 + 5], ymm4);
                vgatherqpd(ymm7, ptr[eax + ymm0], ymm4);
                vgatherqpd(ymm7, ptr[esp + ymm4], ymm4);
                vgatherdpd(ymm7, ptr[xmm0 + r11], ymm4);
                vgatherdpd(ymm7, ptr[r13 + xmm15], ymm4);
                vgatherdpd(ymm7, ptr[123 + rsi + xmm2 * 4], ymm4);
            }
        }
    }
    auto c = new Code();
    //c.dump();
}
