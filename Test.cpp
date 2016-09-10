#include "Logger.h"

int main()
{
    slog::SyncLogger logger("test.log", 200 * 1024 * 1024, 1);

    for (int i = 0; i < 1000000; ++i)
    {
        logger.Info("{}: Just test {} {} {} {} {too} {} , this is long length test log message for my slog...",
                    i, slog::hex(10), slog::HEX(11), ' ', slog::hex('c'), "{long}");
    }

    return 0;
}
