#include "Logger.h"

int main()
{
    auto logger = slog::CreateLogger<slog::SyncLogger>("test.log", 200 * 1024 * 1024, 1);

    for (int i = 0; i < 1000000; ++i)
        logger->Info("[slog] message #{} : This is some text for your pleasure", i);

    return 0;
}
