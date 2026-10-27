#pragma once

#include "ps4_abi_errors.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace nba16 {

enum class GuestAioState : std::uint8_t {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
};

enum class GuestAioCancelDisposition : std::uint8_t {
    Cancelled,
    InProgress,
    AlreadyComplete,
};

struct GuestAioCompletion {
    std::int64_t return_value{-1};
    Ps4Errno error{Ps4Errno::Io};
};

struct GuestAioSnapshot {
    GuestAioState state{GuestAioState::Queued};
    std::int64_t return_value{-1};
    Ps4Errno error{Ps4Errno::Success};
    int descriptor{-1};
};

// Owns asynchronous jobs for one guest process. Jobs are serialized in
// submission order so a later fsync job can act as an ordering barrier.
class GuestAioRuntime {
public:
    using Work = std::function<GuestAioCompletion()>;

    GuestAioRuntime();
    ~GuestAioRuntime();
    GuestAioRuntime(const GuestAioRuntime&) = delete;
    GuestAioRuntime& operator=(const GuestAioRuntime&) = delete;

    bool submit(std::uint64_t control_block, int descriptor, Work work,
                std::string& error);
    bool cancel(std::uint64_t control_block, int descriptor,
                GuestAioCancelDisposition& disposition, std::string& error);
    bool cancel_descriptor(int descriptor,
                           GuestAioCancelDisposition& disposition,
                           std::vector<std::uint64_t>& cancelled,
                           std::string& error);
    bool wait(std::span<const std::uint64_t> control_blocks, bool wait_all,
              std::optional<std::chrono::nanoseconds> timeout,
              std::string& error);
    bool wait_descriptor(int descriptor,
                         std::optional<std::chrono::nanoseconds> timeout,
                         std::string& error);
    [[nodiscard]] std::optional<GuestAioSnapshot> snapshot(
        std::uint64_t control_block) const;
    bool forget(std::uint64_t control_block, std::string& error);

private:
    struct Request {
        std::uint64_t control_block{};
        int descriptor{-1};
        Work work;
        GuestAioSnapshot result{};
    };

    static bool is_finished(GuestAioState state) noexcept;
    void worker_loop() noexcept;

    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::map<std::uint64_t, Request> requests_;
    std::deque<std::uint64_t> queue_;
    bool stopping_{};
    std::thread worker_;
};

} // namespace nba16
