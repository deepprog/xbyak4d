module protect_re;

import core.stdc.stdio;
import core.stdc.stdlib;

import xbyak;

class Code1 : CodeGenerator
{
    this()
    {
        super(4096, DontSetProtectRWE);

        mov(eax, 123);
        ret();
    }
    void update()
    {
        db(0);
    }
}

void test1(bool updateCode)
{
    Code1 c = new Code1();
    c.setProtectModeRE();
    if (updateCode) c.update(); // segmentation fault
    auto f = c.getCode!(int function())();
    printf("f=%d\n", f());
    
    c.setProtectModeRW();
    c.update();
    puts("ok");
}

class Code2 : CodeGenerator
{
    this()
    {
        super(4096, AutoGrow);
        mov(eax, 123);
        ret();
    }
    void update()
    {
        db(0);
    }
}

void test2(bool updateCode)
{
    Code2 c = new Code2();
    c.readyRE();
    if (updateCode) c.update(); // segmentation fault
    auto f = c.getCode!(int function())();
    printf("f=%d\n", f());
    
    c.setProtectModeRW();
    c.update();
    puts("ok");
}

extern(C) int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "./protect_re <testNum> [update]\n", argv[0]);
        return 0;
    }
    bool update = argc == 3;
    int n = atoi(argv[1]);
    printf("n=%d update=%d\n", n, update);
    switch (n) {
    case 1: test1(update); break;
    case 2: test2(update); break;
    default: fprintf(stderr, "no test %d\n", n); break;
    }
    return 0;
}
