#include "Logger.h"

struct Test
{
    int i;
    int j;
};

inline slog::ArgFormatter & operator << (slog::ArgFormatter &f, const Test &t)
{
    f << "{ i: " << t.i << ", j: " << t.j << " }";
    return f;
}

int main()
{
    slog::SyncLogger logger("test.log", 200 * 1024 * 1024, 1);

    for (int i = 0; i < 1000000; ++i)
        logger.Info("[slog] message #{} : This is some text for your pleasure", i);

    Test t1{ 1, 2 };
    Test t2{ 3, 4 };

    logger.Info("{}, {}", t1, t2);

    return 0;
}
