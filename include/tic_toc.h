#pragma once

#include <chrono> // for std::chrono functions
#include <iostream>
#include <string_view>

/**
 * Help class for time measuring
 */
class Timer
{
private:
    // Type aliases to make accessing nested type easier
    using Clock = std::chrono::steady_clock;
    using Second = std::chrono::duration<double, std::ratio<1>>;

    std::chrono::time_point<Clock> beg_;

public:
    void tic()
    {
        beg_ = Clock::now();
    }

    double tocr() const
    {
        return std::chrono::duration_cast<Second>(Clock::now() - beg_).count();
    }

    double toc(std::string_view s) const
    {
        double t = tocr();
        std::cout << s << ": " << t << " s" << '\n';
        return t;
    }

    double toc() const
    {
        return toc("Timer");
    }
};
