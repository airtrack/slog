#ifndef LOGGER_H
#define LOGGER_H

#include <sys/stat.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stddef.h>

#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace slog
{

class ArgListBuf final
{
public:
    struct ArgBufRef final
    {
        const char *buf = nullptr;
        const char *end = nullptr;

        std::size_t Size() const
        {
            return end - buf;
        }
    };

    ArgListBuf() = default;

    ~ArgListBuf()
    {
        if (buf_ != fixed_buf_)
            delete [] buf_;

        if (arg_list_ != fixed_args_)
            delete [] arg_list_;
    }

    ArgListBuf(const ArgListBuf &) = delete;
    void operator = (const ArgListBuf &) = delete;

    void ReserveBuf(std::size_t size)
    {
        if (size_ + size > capacity_)
        {
            auto new_capacity_ = (size_ + size) * 3 / 2;
            auto new_buf_ = new char[new_capacity_];
            memcpy(new_buf_, buf_, size_);

            if (buf_ != fixed_buf_)
                delete [] buf_;

            buf_ = new_buf_;
            capacity_ = new_capacity_;
        }
    }

    char * Current()
    {
        return buf_ + size_;
    }

    void PushArgInfo(std::size_t arg_buf_size)
    {
        if (arg_count_ >= arg_list_size_)
            IncreaseArgInfoList();

        arg_list_[arg_count_].index = size_;
        arg_list_[arg_count_].size = arg_buf_size;

        ++arg_count_;
        size_ += arg_buf_size;
    }

    std::size_t ArgCount() const
    {
        return arg_count_;
    }

    ArgBufRef operator [] (std::size_t index) const
    {
        if (index >= arg_count_)
            return ArgBufRef();

        ArgBufRef arg_buf_ref;
        auto &arg_info = arg_list_[index];

        arg_buf_ref.buf = buf_ + arg_info.index;
        arg_buf_ref.end = arg_buf_ref.buf + arg_info.size;
        return arg_buf_ref;
    }

private:
    struct ArgInfo final
    {
        unsigned int index;
        unsigned int size;
    };

    void IncreaseArgInfoList()
    {
        auto new_arg_list_size = arg_list_size_ * 3 / 2;
        auto new_arg_list = new ArgInfo[new_arg_list_size];
        memcpy(new_arg_list, arg_list_, arg_list_size_ * sizeof(ArgInfo));

        if (arg_list_ != fixed_args_)
            delete [] arg_list_;

        arg_list_ = new_arg_list;
        arg_list_size_ = new_arg_list_size;
    }

    static const std::size_t kFixedSize = 512;
    static const std::size_t kFixedArgCount = 16;

    char fixed_buf_[kFixedSize];
    ArgInfo fixed_args_[kFixedArgCount];

    // Args buffer
    char *buf_ = fixed_buf_;
    std::size_t capacity_ = kFixedSize;
    std::size_t size_ = 0;

    // Args list
    ArgInfo *arg_list_ = fixed_args_;
    std::size_t arg_list_size_ = kFixedArgCount;
    std::size_t arg_count_ = 0;
};

class ArgFormatter final
{
public:
    explicit ArgFormatter(ArgListBuf &arg_list_buf)
        : arg_list_buf_(arg_list_buf)
    {
    }

    ~ArgFormatter()
    {
        arg_list_buf_.PushArgInfo(arg_data_size_);
    }

    ArgFormatter(const ArgFormatter &) = delete;
    void operator = (const ArgFormatter &) = delete;

    void Append(const char *buf, std::size_t size)
    {
        ReserveBuf(size);
        memcpy(Current(), buf, size);
        ConsumeBuf(size);
    }

private:
    void ReserveBuf(std::size_t size)
    {
        arg_list_buf_.ReserveBuf(arg_data_size_ + size);
    }

    char * Current()
    {
        return arg_list_buf_.Current() + arg_data_size_;
    }

    void ConsumeBuf(std::size_t size)
    {
        arg_data_size_ += size;
    }

    ArgListBuf &arg_list_buf_;
    std::size_t arg_data_size_ = 0;
};

#define ARG_FORMATTER(type, fmt, buf_size) \
    inline ArgFormatter & operator << (ArgFormatter &f, type t) \
    { \
        char buf[buf_size] = { 0 }; \
        auto size = snprintf(buf, sizeof(buf), fmt, t); \
        f.Append(buf, size); \
        return f; \
    }

ARG_FORMATTER(short, "%hd", 8)
ARG_FORMATTER(unsigned short, "%hu", 8)
ARG_FORMATTER(int, "%d", 12)
ARG_FORMATTER(unsigned int, "%u", 12)
ARG_FORMATTER(long, "%ld", 24)
ARG_FORMATTER(unsigned long, "%ld", 24)
ARG_FORMATTER(long long, "%lld", 24)
ARG_FORMATTER(unsigned long long, "%llu", 24)

inline ArgFormatter & operator << (ArgFormatter &f, char c)
{
    f.Append(&c, sizeof(c));
    return f;
}

inline ArgFormatter & operator << (ArgFormatter &f, signed char c)
{
    return (f << static_cast<char>(c));
}

inline ArgFormatter & operator << (ArgFormatter &f, unsigned char c)
{
    return (f << static_cast<char>(c));
}

inline ArgFormatter & operator << (ArgFormatter &f, const char *s)
{
    f.Append(s, strlen(s));
    return f;
}

inline ArgFormatter & operator << (ArgFormatter &f, std::string &s)
{
    f.Append(s.data(), s.size());
    return f;
}

template<typename IntType>
class Hex1 final
{
public:
    explicit Hex1(IntType v) : v_(v) { }

    IntType GetValue() const { return v_; }

private:
    IntType v_;
};

template<typename IntType>
class Hex2 final
{
public:
    explicit Hex2(IntType v) : v_(v) { }

    IntType GetValue() const { return v_; }

private:
    IntType v_;
};

template<typename IntType>
inline Hex1<IntType> hex(IntType v)
{
    return Hex1<IntType>(v);
}

template<typename IntType>
inline Hex2<IntType> HEX(IntType v)
{
    return Hex2<IntType>(v);
}

#define ARG_HEX_FORMATTER(func_name, type, fmt, buf_size) \
    inline ArgFormatter & func_name(ArgFormatter &f, type t) \
    { \
        char buf[buf_size] = { 0 }; \
        auto size = snprintf(buf, sizeof(buf), fmt, t); \
        f.Append(buf, size); \
        return f; \
    }

#define ARG_HEX1_FORMATTER(type, fmt, buf_size) \
    ARG_HEX_FORMATTER(Hex1Format, type, fmt, buf_size)

#define ARG_HEX2_FORMATTER(type, fmt, buf_size) \
    ARG_HEX_FORMATTER(Hex2Format, type, fmt, buf_size)

ARG_HEX1_FORMATTER(char, "%hhx", 4);
ARG_HEX1_FORMATTER(signed char, "%hhx", 4);
ARG_HEX1_FORMATTER(unsigned char, "%hhx", 4);
ARG_HEX1_FORMATTER(short, "%hx", 6);
ARG_HEX1_FORMATTER(unsigned short, "%hx", 6);
ARG_HEX1_FORMATTER(int, "%x", 10);
ARG_HEX1_FORMATTER(unsigned int, "%x", 10);
ARG_HEX1_FORMATTER(long, "%lx", 18);
ARG_HEX1_FORMATTER(unsigned long, "%lx", 18);
ARG_HEX1_FORMATTER(long long, "%llx", 18);
ARG_HEX1_FORMATTER(unsigned long long, "%llx", 18);

ARG_HEX2_FORMATTER(char, "%hhX", 4);
ARG_HEX2_FORMATTER(signed char, "%hhX", 4);
ARG_HEX2_FORMATTER(unsigned char, "%hhX", 4);
ARG_HEX2_FORMATTER(short, "%hX", 6);
ARG_HEX2_FORMATTER(unsigned short, "%hX", 6);
ARG_HEX2_FORMATTER(int, "%X", 10);
ARG_HEX2_FORMATTER(unsigned int, "%X", 10);
ARG_HEX2_FORMATTER(long, "%lX", 18);
ARG_HEX2_FORMATTER(unsigned long, "%lX", 18);
ARG_HEX2_FORMATTER(long long, "%llX", 18);
ARG_HEX2_FORMATTER(unsigned long long, "%llX", 18);

template<typename IntType>
inline ArgFormatter & operator << (ArgFormatter &f, const Hex1<IntType> &v)
{
    return Hex1Format(f, v.GetValue());
}

template<typename IntType>
inline ArgFormatter & operator << (ArgFormatter &f, const Hex2<IntType> &v)
{
    return Hex2Format(f, v.GetValue());
}

enum class LogLevel
{
    Error,
    Info,
    Debug,
    Trace,
};

class Logger
{
public:
    Logger() = default;
    virtual ~Logger() = default;

    Logger(const Logger &) = delete;
    void operator = (const Logger &) = delete;

    void SetLogLevel(LogLevel log_level)
    {
        log_level_ = log_level;
    }

    template<typename... Args>
    void Error(const char *format, const Args&... args)
    {
        Log(LogLevel::Error, format, args...);
    }

    template<typename... Args>
    void Info(const char *format, const Args&... args)
    {
        Log(LogLevel::Info, format, args...);
    }

    template<typename... Args>
    void Debug(const char *format, const Args&... args)
    {
        Log(LogLevel::Debug, format, args...);
    }

    template<typename... Args>
    void Trace(const char *format, const Args&... args)
    {
        Log(LogLevel::Trace, format, args...);
    }

    template<typename... Args>
    void Log(LogLevel log_level, const char *format, const Args&... args)
    {
        if (!NeedLog(log_level))
            return ;

        ArgListBuf arg_list_buf;
        FormatArgs(arg_list_buf, args...);
        LogFormat(format, arg_list_buf);
    }

protected:
    template<typename PutChar, typename PutBuffer>
    void Format(const char *format, const ArgListBuf &arg_list_buf,
                PutChar &put_char, PutBuffer &put_buffer)
    {
        auto p = format;
        std::size_t index = 0;

        while (*p)
        {
            if (*p == '{')
            {
                if (*(p + 1) == '}')
                {
                    auto arg = arg_list_buf[index];
                    if (arg.buf)
                        put_buffer(arg.buf, arg.Size());
                    ++index;

                    p += 2;
                    continue;
                }
            }

            put_char(*p++);
        }

        put_char('\n');
    }

private:
    template<typename Arg, typename... Args>
    void FormatArgs(ArgListBuf &arg_list_buf,
                    const Arg &arg, const Args&... args)
    {
        {
            ArgFormatter formatter(arg_list_buf);
            formatter << arg;
        }
        FormatArgs(arg_list_buf, args...);
    }

    void FormatArgs(ArgListBuf &arg_list_buf)
    {
        (void)arg_list_buf;
    }

    bool NeedLog(LogLevel log_level) const
    {
        return static_cast<int>(log_level) <=
            static_cast<int>(log_level_);
    }

    virtual void LogFormat(const char *format,
                           const ArgListBuf &arg_list_buf) = 0;

    LogLevel log_level_ = LogLevel::Info;
};

class ConsoleLogger final : public Logger
{
    virtual void LogFormat(const char *format,
                           const ArgListBuf &arg_list_buf) override
    {
        auto put_char = [] (int c) { fputc(c, stdout); };
        auto put_buffer = [] (const char *buf, std::size_t size) {
            fwrite(buf, 1, size, stdout);
        };

        Format(format, arg_list_buf, put_char, put_buffer);
    }
};

class LogMessage final
{
public:
    LogMessage()
    {
        message_.reserve(kInitBufferSize);
    }

    ~LogMessage() = default;

    LogMessage(const LogMessage &) = delete;
    void operator = (const LogMessage &) = delete;

    LogMessage(LogMessage &&other)
        : message_(std::move(other.message_))
    {
    }

    LogMessage & operator = (LogMessage &&other)
    {
        message_ = std::move(other.message_);
        return *this;
    }

    void PutChar(int c)
    {
        message_.push_back(c);
    }

    void PutBuffer(const char *buffer, std::size_t size)
    {
        message_.insert(message_.end(), buffer, buffer + size);
    }

    const char * Data() const
    {
        return message_.data();
    }

    std::size_t Size() const
    {
        return message_.size();
    }

private:
    static const std::size_t kInitBufferSize = 512;

    std::vector<char> message_;
};

class MessageLogger : public Logger
{
    virtual void LogFormat(const char *format,
                           const ArgListBuf &arg_list_buf) override
    {
        LogMessage log_msg;
        auto put_char = [&] (int c) { log_msg.PutChar(c); };
        auto put_buffer = [&] (const char *buf, std::size_t size) {
            log_msg.PutBuffer(buf, size);
        };

        Format(format, arg_list_buf, put_char, put_buffer);
        Sink(std::move(log_msg));
    }

    virtual void Sink(LogMessage log_msg) = 0;
};

class RotateLogSink final
{
public:
    RotateLogSink(const std::string &log_file_name,
                  std::size_t file_size,
                  std::size_t rotate_file_count)
        : log_file_name_(log_file_name),
          log_file_size_(file_size),
          log_rotate_count_(rotate_file_count)
    {
    }

    ~RotateLogSink()
    {
        if (log_)
            fclose(log_);
    }

    RotateLogSink(const RotateLogSink &) = delete;
    void operator = (const RotateLogSink &) = delete;

    void Sink(const LogMessage &log_msg)
    {
        WriteLog(log_, log_msg);
    }

private:
    void WriteLog(FILE *&log, const LogMessage &log_msg)
    {
        if (!log)
        {
            log = fopen(log_file_name_.c_str(), "a");
            if (!log)
                return ;

            writed_size_ = ftell(log);
        }

        writed_size_ += fwrite(log_msg.Data(), 1, log_msg.Size(), log);

        if (writed_size_ >= log_file_size_)
            RotateLogs(log);
    }

    void RotateLogs(FILE *&log)
    {
        fclose(log);
        log = nullptr;
        writed_size_ = 0;

        for (auto i = log_rotate_count_; i > 0; --i)
        {
            char to[256] = { 0 };
            char from[256] = { 0 };

            snprintf(to, sizeof(to), "%s.%zu",
                     log_file_name_.c_str(), i);

            if (i - 1 == 0)
            {
                snprintf(from, sizeof(from), "%s",
                         log_file_name_.c_str());
            }
            else
            {
                snprintf(from, sizeof(from), "%s.%zu",
                         log_file_name_.c_str(), i - 1);
            }

            if (FileExists(to))
                remove(to);

            if (rename(from, to) == 0 && i == log_rotate_count_)
                remove(to);
        }
    }

    bool FileExists(const char *file_name)
    {
        struct stat buffer;
        return stat(file_name, &buffer) == 0;
    }

    std::string log_file_name_;
    std::size_t log_file_size_;
    std::size_t log_rotate_count_;
    std::size_t writed_size_ = 0;
    FILE *log_ = nullptr;
};

class SyncLogger final : public MessageLogger
{
public:
    SyncLogger(const std::string &log_file_name,
               std::size_t file_size,
               std::size_t rotate_file_count)
        : rotate_log_sink_(log_file_name, file_size, rotate_file_count)
    {
    }

    SyncLogger(const SyncLogger &) = delete;
    void operator = (const SyncLogger &) = delete;

private:
    virtual void Sink(LogMessage log_msg) override
    {
        rotate_log_sink_.Sink(log_msg);
    }

    RotateLogSink rotate_log_sink_;
};

template<typename T>
class BoundedQueue final
{
public:
    explicit BoundedQueue(std::size_t max_size)
        : max_size_(max_size)
    {
    }

    BoundedQueue(const BoundedQueue &) = delete;
    void operator = (const BoundedQueue &) = delete;

    bool Push(T &&t)
    {
        {
            std::lock_guard<std::mutex> l(mutex_);
            if (queue_.size() >= max_size_)
                return false;
            queue_.push(std::move(t));
        }

        cond_var_.notify_one();
        return true;
    }

    T Pop()
    {
        T t;

        {
            std::unique_lock<std::mutex> l(mutex_);
            cond_var_.wait(l, [this] () { return !queue_.empty(); });
            t = std::move(queue_.front());
            queue_.pop();
        }

        return std::move(t);
    }

private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cond_var_;
    std::size_t max_size_;
};

class AsyncLogger final : public MessageLogger
{
public:
    AsyncLogger(const std::string &log_file_name,
                std::size_t file_size,
                std::size_t rotate_file_count,
                std::size_t queue_size)
        : rotate_log_sink_(log_file_name, file_size, rotate_file_count),
          log_msg_queue_(queue_size),
          log_thread_(&AsyncLogger::LogThreadFunc, this)
    {
    }

    ~AsyncLogger()
    {
        PushAsyncMsg(AsyncLogMessage());
        log_thread_.join();
    }

private:
    enum class MessageType
    {
        Log,
        Terminate,
    };

    struct AsyncLogMessage final
    {
        MessageType msg_type;
        LogMessage log_msg;

        AsyncLogMessage()
            : msg_type(MessageType::Terminate)
        {
        }

        explicit AsyncLogMessage(LogMessage &&log_msg)
            : msg_type(MessageType::Log),
              log_msg(std::move(log_msg))
        {
        }

        AsyncLogMessage(AsyncLogMessage &&other)
            : msg_type(other.msg_type),
              log_msg(std::move(other.log_msg))
        {
        }

        AsyncLogMessage & operator = (AsyncLogMessage &&other)
        {
            msg_type = other.msg_type;
            log_msg = std::move(other.log_msg);
            return *this;
        }
    };

    void LogThreadFunc()
    {
        for (;;)
        {
            auto msg = log_msg_queue_.Pop();

            if (msg.msg_type == MessageType::Terminate)
                break;

            rotate_log_sink_.Sink(msg.log_msg);
        }
    }

    void PushAsyncMsg(AsyncLogMessage async_log_msg)
    {
        while (!log_msg_queue_.Push(std::move(async_log_msg)))
            usleep(100);
    }

    virtual void Sink(LogMessage log_msg) override
    {
        PushAsyncMsg(AsyncLogMessage(std::move(log_msg)));
    }

    RotateLogSink rotate_log_sink_;
    BoundedQueue<AsyncLogMessage> log_msg_queue_;
    std::thread log_thread_;
};

} // namespace slog

#endif // LOGGER_H
