module test.bad_address;

unittest
{
    import xbyak4d;
    import std.exception;

    class Code : CodeGenerator
    {
        this()
        {
            static assert(!__traits(compiles, mov(eax, ptr [esp + esp])));
            static assert(!__traits(compiles, mov(eax, ptr [ax])));             // not support
            assertThrown(mov(eax, ptr [esp * 4]));
            assertThrown(mov(eax, ptr [eax * 16]));
            static assert(!__traits(compiles, mov(eax, ptr [eax + eax + eax])));
            assertThrown(mov(eax, ptr [eax * 2 + ecx * 4]));
            assertThrown(mov(eax, ptr [eax * 2 + ecx * 4]));
            assertThrown(vgatherdpd(xmm0, ptr [eax * 2], ymm3));
            static assert(!__traits(compiles, vgatherdpd(xmm0, ptr [xmm0 + xmm1], ymm3)));
            version(XBYAK64)
            {
                static assert(!__traits(compiles, mov(eax, ptr [rax + eax])));
                static assert(!__traits(compiles, mov(eax, ptr [xmm0 + ymm0])));
            }
        }
    }
    auto c = new Code;
}