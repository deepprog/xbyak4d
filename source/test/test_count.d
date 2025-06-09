module test.test_count;

import std.stdio;


struct TestCount
{
    void reset()
    {
        okCount_ = 0;
        ngCount_ = 0;
    }

    void set(bool isOK)
    {
        if (isOK) {
            okCount_++;
        } else {
            ngCount_++;
        }
    }

    void test(bool ret, string msg, string param, string file, size_t line)
    {
        this.set(ret);
        if (!ret) {
            writefln("%s(%d): TestCount.%s(%s);", file, line, msg, param);
        }
    }

    void TEST_EQUAL(T)(T x, T y, string file = __FILE__, size_t line = __LINE__)
    {
        auto isEqual = (x == y);
        this.test(isEqual, "TEST_EQUAL", x.stringof ~ ", " ~ y.stringof, file, line);

        if (!isEqual) {
            writeln("test: lhs = ", x);
            writeln("test: rhs = ", y);
        }
    }

    void end(string name = "")
    {
        writeln(name, " OK:", okCount_, " NG:", ngCount_);
        assert(ngCount_ == 0);
    }

private:
    int okCount_;
    int ngCount_;
}
