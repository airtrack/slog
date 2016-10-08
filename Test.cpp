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
    auto logger = slog::CreateLogger<slog::ConsoleLogger>();

    Test t1{ 1, 2 };
    Test t2{ 3, 4 };

    logger->Info("{1} {0}", t1, t2);
    logger->Info("{:20} {:20}", t1, t2);
    logger->Info("{1:20} {0:20}", t1, t2);
    logger->Info("{:>20} {:>20}", t1, t2);
    logger->Info("{:<20} {:<20}", t1, t2);
    logger->Info("{:^20} {:^20}", t1, t2);
    logger->Info("{:^#20} {:^#20}", t1, t2);
    logger->Info("{} {}", &t1, &t2);

    return 0;
}
