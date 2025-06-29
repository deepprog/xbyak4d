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
        if (isOK)
        {
            okCount_++;
        }
        else
        {
            ngCount_++;
        }
    }

    void test(bool ret, string msg, string param, string file, size_t line)
    {
        this.set(ret);
        if (!ret)
        {
            writefln("%s(%d): TestCount.%s(%s);", file, line, msg, param);
        }
    }

    void TEST_ASSERT(bool x, string file = __FILE__, size_t line = __LINE__)
    {
        this.test(x, "TEST_ASSERT", x.stringof, file, line);
    }

    void TEST_EQUAL(T)(T x, T y, string file = __FILE__, size_t line = __LINE__)
    {
        auto isEqual = (x == y);
        this.test(isEqual, "TEST_EQUAL", x.stringof ~ ", " ~ y.stringof, file, line);

        if (!isEqual)
        {
            writeln("test: lhs = ", x);
            writeln("test: rhs = ", y);
        }
    }

    void TEST_EXCEPTION(T : Throwable)(void delegate() statement, string file = __FILE__, size_t line = __LINE__)
    {
        int ret_ = 0;
        try
        {
            statement();
            ret_ = 1;
        }
        catch (T ex)
        {
            // ret_ = 0;
        }
        catch (Throwable t)
        {
            ret_ = 2;
        }

        if (ret_ == 0)
        {
            okThrowCount_++;
            return;
        }

        if (ret_ != 0)
        {
            ngThrowCount_++;
            writeln("TEST_EXCEPTION: Failure in ", file, " line ", line);
            if (ret_ == 1)
            {
                writeln("test: no Exception");
            }
            else
            {
                writeln("test: unexpected Exception");
            }
        }
    }

    void end(string name = "")
    {
        write(name, " OK:", okCount_, " NG:", ngCount_);
        if(okThrowCount_ == 0 && ngThrowCount_ == 0)
        {
            writeln();
        }
        else
        {
            writeln(" Throw_OK:", okThrowCount_, " Throw_NG:", ngThrowCount_);
        }
        writeln();
        assert(ngCount_ == 0);
        assert(ngThrowCount_ == 0);
    }

private:
    int okCount_;
    int ngCount_;

    int okThrowCount_ = 0;
    int ngThrowCount_ = 0;
}
