#include "logger.hpp"
#include <iostream>
#include <thread>
#include <sstream>
#include <chrono>
#include <iomanip>

// Static member definitions
LogLevel Logger::current_level_ = LogLevel::INFO;
std::mutex Logger::log_mutex_;
bool Logger::colors_enabled_ = true;
bool Logger::timestamps_enabled_ = true;

std::string Logger::get_timestamp()
{
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string Logger::get_level_string(LogLevel level)
{
    switch (level)
    {
    case LogLevel::DEBUG:
        return colors_enabled_ ? "\033[34m[DEBUG]\033[0m" : "[DEBUG]";
    case LogLevel::INFO:
        return colors_enabled_ ? "\033[32m[INFO] \033[0m" : "[INFO] ";
    case LogLevel::WARNING:
        return colors_enabled_ ? "\033[33m[WARN] \033[0m" : "[WARN] ";
    case LogLevel::ERROR:
        return colors_enabled_ ? "\033[31m[ERROR]\033[0m" : "[ERROR]";
    case LogLevel::FATAL:
        return colors_enabled_ ? "\033[35m[FATAL]\033[0m" : "[FATAL]";
    default:
        return "[UNKNOWN]";
    }
}

std::string Logger::get_thread_info(const std::string &thread_name)
{
    if (!thread_name.empty())
    {
        return colors_enabled_ ? "\033[36m[" + thread_name + "]\033[0m" : "[" + thread_name + "]";
    }
    return "";
}

void Logger::set_level(LogLevel level)
{
    current_level_ = level;
}

void Logger::enable_colors(bool enable)
{
    colors_enabled_ = enable;
}

void Logger::enable_timestamps(bool enable)
{
    timestamps_enabled_ = enable;
}

void Logger::log(LogLevel level, const std::string &message, const std::string &thread_name, const std::string &component)
{
    if (level < current_level_)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(log_mutex_);

    std::ostringstream log_line;

    // Add timestamp if enabled
    if (timestamps_enabled_)
    {
        log_line << get_timestamp() << " ";
    }

    // Add log level
    log_line << get_level_string(level) << " ";

    // Add thread info if provided
    if (!thread_name.empty())
    {
        log_line << get_thread_info(thread_name) << " ";
    }

    // Add component if provided
    if (!component.empty())
    {
        if (colors_enabled_)
        {
            log_line << "\033[36m[" << component << "]\033[0m ";
        }
        else
        {
            log_line << "[" << component << "] ";
        }
    }

    // Add the actual message
    log_line << message;

    std::cout << log_line.str() << std::endl;
}

void Logger::debug(const std::string &message, const std::string &thread_name, const std::string &component)
{
    log(LogLevel::DEBUG, message, thread_name, component);
}

void Logger::info(const std::string &message, const std::string &thread_name, const std::string &component)
{
    log(LogLevel::INFO, message, thread_name, component);
}

void Logger::warning(const std::string &message, const std::string &thread_name, const std::string &component)
{
    log(LogLevel::WARNING, message, thread_name, component);
}

void Logger::error(const std::string &message, const std::string &thread_name, const std::string &component)
{
    log(LogLevel::ERROR, message, thread_name, component);
}

void Logger::fatal(const std::string &message, const std::string &thread_name, const std::string &component)
{
    log(LogLevel::FATAL, message, thread_name, component);
}