#ifndef LOGGER_H
#define LOGGER_H

#include <sys/stat.h>
#include <unistd.h>

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <deque>
#include <mutex>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <type_traits>
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

template<typename IntType>
inline std::size_t GetDigitCount(IntType u, std::size_t base)
{
    std::size_t digits = 0;
    do
    {
        ++digits;
        u /= base;
    } while (u);
    return digits;
}

template<typename IntType>
inline std::size_t UnsafeToStr(char *buf, std::size_t width, IntType u,
                               std::size_t base, const char *table)
{
    width = std::max(GetDigitCount(u, base), width);

    auto pos = width;

    for (; u > 0; u /= base)
        buf[--pos] = table[u % base];

    // Pad '0'
    while (pos > 0)
        buf[--pos] = '0';

    return width;
}

template<typename IntType>
inline std::size_t UnsafeToHex(char *buf, std::size_t width, IntType u)
{
    const char *table = "0123456789abcdef";
    return UnsafeToStr(buf, width,
                       typename std::make_unsigned<IntType>::type(u),
                       16, table);
}

template<typename IntType>
inline std::size_t UnsafeToHEX(char *buf, std::size_t width, IntType u)
{
    const char *table = "0123456789ABCDEF";
    return UnsafeToStr(buf, width,
                       typename std::make_unsigned<IntType>::type(u),
                       16, table);
}

template<typename IntType>
inline std::size_t UnsafeToDecimal(char *buf, std::size_t width, IntType u,
                                   std::true_type)
{
    const char *table = "0123456789";
    return UnsafeToStr(buf, width, u, 10, table);
}

template<typename IntType>
inline std::size_t UnsafeToDecimal(char *buf, std::size_t width, IntType i,
                                   std::false_type)
{
    std::size_t pos = 0;
    typename std::make_unsigned<IntType>::type u = 0;

    if (i >= 0)
        u = i;
    else
    {
        buf[pos++] = '-';
        u = -i;
    }

    return pos + UnsafeToDecimal(buf + pos, width == 0 ? 0 : width - pos, u,
                                 std::true_type());
}

template<typename IntType>
inline std::size_t UnsafeToDecimal(char *buf, std::size_t width, IntType i)
{
    return UnsafeToDecimal(buf, width, i, std::is_unsigned<IntType>());
}

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

    void AppendChar(int c)
    {
        ReserveBuf(1);
        *Current() = c;
        ConsumeBuf(1);
    }

    void Append(const char *buf, std::size_t size)
    {
        ReserveBuf(size);
        memcpy(Current(), buf, size);
        ConsumeBuf(size);
    }

    template<typename T>
    void ToDecimal(T t, std::size_t reserve)
    {
        ReserveBuf(reserve);
        ConsumeBuf(UnsafeToDecimal(Current(), 0, t));
    }

    template<typename T>
    void ToHex(T t, std::size_t reserve)
    {
        ReserveBuf(reserve);
        ConsumeBuf(UnsafeToHex(Current(), 0, t));
    }

    template<typename T>
    void ToHEX(T t, std::size_t reserve)
    {
        ReserveBuf(reserve);
        ConsumeBuf(UnsafeToHEX(Current(), 0, t));
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

#define ARG_FORMATTER_TO_DECIMAL(type, buf_size) \
    inline ArgFormatter & operator << (ArgFormatter &f, type t) \
    { \
        f.ToDecimal(t, buf_size); \
        return f; \
    }

ARG_FORMATTER_TO_DECIMAL(short, 6)
ARG_FORMATTER_TO_DECIMAL(unsigned short, 5)
ARG_FORMATTER_TO_DECIMAL(int, 11)
ARG_FORMATTER_TO_DECIMAL(unsigned int, 10)
ARG_FORMATTER_TO_DECIMAL(long, 20)
ARG_FORMATTER_TO_DECIMAL(unsigned long, 20)
ARG_FORMATTER_TO_DECIMAL(long long, 20)
ARG_FORMATTER_TO_DECIMAL(unsigned long long, 20)

inline ArgFormatter & operator << (ArgFormatter &f, char c)
{
    f.AppendChar(c);
    return f;
}

inline ArgFormatter & operator << (ArgFormatter &f, signed char c)
{
    f.AppendChar(c);
    return f;
}

inline ArgFormatter & operator << (ArgFormatter &f, unsigned char c)
{
    f.AppendChar(c);
    return f;
}

inline ArgFormatter & operator << (ArgFormatter &f, const char *s)
{
    f.Append(s, strlen(s));
    return f;
}

inline ArgFormatter & operator << (ArgFormatter &f, const std::string &s)
{
    f.Append(s.data(), s.size());
    return f;
}

inline ArgFormatter & operator << (ArgFormatter &f, void *p)
{
    f.Append("0x", 2);
    f.ToHex(reinterpret_cast<uintptr_t>(p), sizeof(p) * 2);
    return f;
}

inline ArgFormatter & operator << (ArgFormatter &f, float d)
{
    std::ostringstream oss;
    oss << d;
    return f << oss.str();
}

inline ArgFormatter & operator << (ArgFormatter &f, double d)
{
    std::ostringstream oss;
    oss << d;
    return f << oss.str();
}

inline ArgFormatter & operator << (ArgFormatter &f, long double d)
{
    std::ostringstream oss;
    oss << d;
    return f << oss.str();
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

#define ARG_HEX_FORMATTER(func_name, type, fmt_func, buf_size) \
    inline ArgFormatter & func_name(ArgFormatter &f, type t) \
    { \
        f.fmt_func(t, buf_size); \
        return f; \
    }

#define ARG_HEX1_FORMATTER(type, buf_size) \
    ARG_HEX_FORMATTER(Hex1Format, type, ToHex, buf_size)

#define ARG_HEX2_FORMATTER(type, buf_size) \
    ARG_HEX_FORMATTER(Hex2Format, type, ToHEX, buf_size)

ARG_HEX1_FORMATTER(char, 2);
ARG_HEX1_FORMATTER(signed char, 2);
ARG_HEX1_FORMATTER(unsigned char, 2);
ARG_HEX1_FORMATTER(short, 4);
ARG_HEX1_FORMATTER(unsigned short, 4);
ARG_HEX1_FORMATTER(int, 8);
ARG_HEX1_FORMATTER(unsigned int, 8);
ARG_HEX1_FORMATTER(long, 16);
ARG_HEX1_FORMATTER(unsigned long, 16);
ARG_HEX1_FORMATTER(long long, 16);
ARG_HEX1_FORMATTER(unsigned long long, 16);

ARG_HEX2_FORMATTER(char, 2);
ARG_HEX2_FORMATTER(signed char, 2);
ARG_HEX2_FORMATTER(unsigned char, 2);
ARG_HEX2_FORMATTER(short, 4);
ARG_HEX2_FORMATTER(unsigned short, 4);
ARG_HEX2_FORMATTER(int, 8);
ARG_HEX2_FORMATTER(unsigned int, 8);
ARG_HEX2_FORMATTER(long, 16);
ARG_HEX2_FORMATTER(unsigned long, 16);
ARG_HEX2_FORMATTER(long long, 16);
ARG_HEX2_FORMATTER(unsigned long long, 16);

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
                const PutChar &put_char, const PutBuffer &put_buffer)
    {
        auto p = format;
        std::size_t index = 0;

        while (*p)
        {
            if (*p == '{')
            {
                if (ParseFmt(p, index, arg_list_buf, put_char, put_buffer))
                    continue;
            }

            put_char(*p++);
        }

        put_char('\n');
    }

private:
    template<typename PutChar, typename PutBuffer>
    bool ParseFmt(const char *&p, std::size_t &index,
                  const ArgListBuf &arg_list_buf,
                  const PutChar &put_char,
                  const PutBuffer &put_buffer)
    {
        if (*(p + 1) == '}')
        {
            if (PutArg(p, p + 1, arg_list_buf, put_buffer, index))
            {
                ++index;
                return true;
            }
        }
        else if (*(p + 1) == ':')
        {
            if (ParseAlign(p, p + 1, arg_list_buf, put_char, put_buffer, index))
            {
                ++index;
                return true;
            }
        }
        else if (isdigit(*(p + 1)))
        {
            if (ParseArgIndex(p, p + 1, arg_list_buf, put_char, put_buffer))
                return true;
        }

        return false;
    }

    template<typename PutBuffer>
    bool PutArg(const char *&p, const char *e,
                const ArgListBuf &arg_list_buf,
                const PutBuffer &put_buffer,
                std::size_t index)
    {
        auto arg = arg_list_buf[index];
        if (arg.buf)
            put_buffer(arg.buf, arg.Size());

        p = e + 1;
        return true;
    }

    template<typename PutChar, typename PutBuffer>
    bool ParseAlign(const char *&p, const char *a,
                    const ArgListBuf &arg_list_buf,
                    const PutChar &put_char,
                    const PutBuffer &put_buffer,
                    std::size_t index)
    {
        a += 1;

        const auto kLeft = 1;
        const auto kRight = 2;
        const auto kCenter = 3;

        auto align = kRight;
        switch (*a)
        {
        case '<': align = kLeft; ++a; break;
        case '>': align = kRight; ++a; break;
        case '^': align = kCenter; ++a; break;
        }

        auto pad = ' ';
        if (!isdigit(*a) || *a == '0')
        {
            pad = *a;
            ++a;
        }

        if (!isdigit(*a))
            return false;

        auto total_size = ParseNumber(a);

        if (*a != '}')
            return false;

        auto size = 0u;
        auto arg = arg_list_buf[index];
        if (arg.buf)
            size = arg.Size();

        auto pad_size = size > total_size ? 0 : total_size - size;
        auto left_pad_size = 0u;
        auto right_pad_size = 0u;

        switch (align)
        {
        case kLeft: right_pad_size = pad_size; break;
        case kRight: left_pad_size = pad_size; break;
        case kCenter:
            left_pad_size = pad_size / 2;
            right_pad_size = pad_size - left_pad_size;
            break;
        }

        for (auto i = 0u; i < left_pad_size; ++i)
            put_char(pad);

        PutArg(p, a, arg_list_buf, put_buffer, index);

        for (auto i = 0u; i < right_pad_size; ++i)
            put_char(pad);
        return true;
    }

    template<typename PutChar, typename PutBuffer>
    bool ParseArgIndex(const char *&p, const char *d,
                       const ArgListBuf &arg_list_buf,
                       const PutChar &put_char,
                       const PutBuffer &put_buffer)
    {
        auto index = ParseNumber(d);

        if (*d == ':')
            return ParseAlign(p, d, arg_list_buf, put_char, put_buffer, index);
        else if (*d == '}')
            return PutArg(p, d, arg_list_buf, put_buffer, index);

        return false;
    }

    unsigned int ParseNumber(const char *&d)
    {
        auto num = 0u;

        while (isdigit(*d))
        {
            num = num * 10 + *d - '0';
            ++d;
        }

        return num;
    }

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
        LogTimestamp(log_msg);

        auto put_char = [&] (int c) { log_msg.PutChar(c); };
        auto put_buffer = [&] (const char *buf, std::size_t size) {
            log_msg.PutBuffer(buf, size);
        };

        Format(format, arg_list_buf, put_char, put_buffer);
        Sink(std::move(log_msg));
    }

    virtual void Sink(LogMessage log_msg) = 0;

    void LogTimestamp(LogMessage &log_msg)
    {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto microseconds = std::chrono::duration_cast<
            std::chrono::microseconds>(now.time_since_epoch()).count();

        microseconds %= 1000000;

        if (time != time_)
        {
            localtime_r(&time, &tm_);
            time_ = time;

            snprintf(timestamp_buffer_, 21, "[%d-%02d-%02d %02d:%02d:%02d",
                     tm_.tm_year + 1900, tm_.tm_mon + 1, tm_.tm_mday,
                     tm_.tm_hour, tm_.tm_min, tm_.tm_sec);
            timestamp_buffer_[20] = '.';
        }

        UnsafeToDecimal(timestamp_buffer_ + 21, 6,
                        static_cast<unsigned int>(microseconds));
        timestamp_buffer_[27] = ']';
        timestamp_buffer_[28] = ' ';

        log_msg.PutBuffer(timestamp_buffer_, sizeof(timestamp_buffer_));
    }

    // Cache time and tm
    time_t time_ = 0;
    struct tm tm_;

    // Timestamp format: [2016-09-11 17:00:00.000123]
    char timestamp_buffer_[29];
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
            queue_.push_back(std::move(t));
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
            queue_.pop_front();
        }

        return std::move(t);
    }

    void Swap(std::deque<T> &queue)
    {
        std::unique_lock<std::mutex> l(mutex_);
        cond_var_.wait(l, [this] () { return !queue_.empty(); });
        queue.swap(queue_);
    }

private:
    std::deque<T> queue_;
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
        std::deque<AsyncLogMessage> msg_queue;

        for (;;)
        {
            log_msg_queue_.Swap(msg_queue);

            for (auto &msg : msg_queue)
            {
                if (msg.msg_type == MessageType::Terminate)
                    return ;

                rotate_log_sink_.Sink(msg.log_msg);
            }

            msg_queue.clear();
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

template<typename LoggerType, typename... Args>
inline std::unique_ptr<Logger> CreateLogger(Args &&... args)
{
    return std::unique_ptr<Logger>(new LoggerType(std::forward<Args>(args)...));
}

} // namespace slog

#endif // LOGGER_H
