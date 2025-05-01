module noexception;

version(XBYAK_NO_EXCEPTION)
{
  version(X86)
  {
    version = XBYAK32;
  }

  version(X86_64)
  {
    version = XBYAK64;
  }


import core.stdc.stdio;
import std.stdint;

import xbyak;

int g_err = 0;
int g_test = 0;

void assertEq(int x, int y)
{
    if (x != y) {
        printf("ERR x=%d y=%d\n", x, y);
        g_err++;
    }
    g_test++;
}

void assertBool(bool b)
{
    if (!b) {
        printf("ERR assertBool\n");
        g_err++;
    }
    g_test++;
}

void test1()
{
    const int v = 123;
    class Code : CodeGenerator {
        this()
        {
            super();
            mov(eax, v);
            ret();
        }
    }
    auto c = new Code();

    auto f = cast(int function())c.getCode();
    assertEq(f(), v);
    assertEq(xbyak.GetError(), ERR.NONE);
}

void test2()
{
    class Code : CodeGenerator {
        this()
        {
            super();
            Label lp;
            L(lp);
            L(lp);
        }
    }
    auto c = new Code();
    assertEq(xbyak.GetError(), ERR.LABEL_IS_REDEFINED);
    xbyak.ClearError();
}

void test3()
{
    uint8_t[128] buf;
    class EmptyAllocator : Allocator {
        override uint8_t* alloc(size_t size) { return buf.ptr; }
    }
    auto emptyAllocator = new EmptyAllocator();
    
    class Code : CodeGenerator
    {
        this()
        {
            super(8, null, emptyAllocator);
            mov(eax, 3);
            assertBool(xbyak.GetError() == 0);
            mov(eax, 3);
            mov(eax, 3);
            assertBool(xbyak.GetError() != 0);
            xbyak.ClearError();
            assertBool(xbyak.GetError() == 0);
        }
    } 
    auto c = new Code();
}

void test4()
{
    class Code : CodeGenerator
    {
        this()
        {
            super();
            mov(ptr[eax], 1);
            assertBool(xbyak.GetError() != 0);
            xbyak.ClearError();

            test(ptr[eax], 1);
            assertBool(xbyak.GetError() != 0);
            xbyak.ClearError();

            adc(ptr[eax], 1);
            assertBool(xbyak.GetError() != 0);
            xbyak.ClearError();

            setz(eax);
            assertBool(xbyak.GetError() != 0);
            xbyak.ClearError();
        }
    }
    auto c = new Code();
}

int main()
{
    test1();
    test2();
    test3();
    test4();
    if (g_err) {
        printf("err %d/%d\n", g_err, g_test);
    } else {
        printf("all ok %d\n", g_test);
    }
    return g_err != 0;
}

}
