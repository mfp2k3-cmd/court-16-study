#include "aio_runtime.h"

#include <utility>

namespace nba16 {

GuestAioRuntime::GuestAioRuntime() : worker_([this] { worker_loop(); }) {}

GuestAioRuntime::~GuestAioRuntime() {
    {
        const std::lock_guard lock(mutex_);
        stopping_ = true;
        for (auto& [control_block, request] : requests_) {
            (void)control_block;
            if (request.result.state == GuestAioState::Queued) {
                request.result.state = GuestAioState::Cancelled;
                request.result.return_value = -1;
                request.result.error = Ps4Errno::Canceled;
            }
        }
        queue_.clear();
    }
    changed_.notify_all();
    if (worker_.joinable()) worker_.join();
}

bool GuestAioRuntime::submit(std::uint64_t control_block, int descriptor,
                             Work work, std::string& error) {
    if (control_block == 0 || descriptor < 0 || !work) {
        error = "bloco de controle, descritor ou operação AIO inválidos";
        return false;
    }
    {
        const std::lock_guard lock(mutex_);
        if (stopping_) {
            error = "o runtime AIO está encerrando";
            return false;
        }
        if (requests_.contains(control_block)) {
            error = "já existe uma requisição AIO para este bloco de controle";
            return false;
        }
        Request request{};
        request.control_block = control_block;
        request.descriptor = descriptor;
        request.work = std::move(work);
        request.result.descriptor = descriptor;
        request.result.state = GuestAioState::Queued;
        request.result.error = Ps4Errno::Success;
        requests_.emplace(control_block, std::move(request));
        queue_.push_back(control_block);
    }
    error.clear();
    changed_.notify_all();
    return true;
}

bool GuestAioRuntime::cancel(std::uint64_t control_block, int descriptor,
                             GuestAioCancelDisposition& disposition,
                             std::string& error) {
    const std::lock_guard lock(mutex_);
    const auto found = requests_.find(control_block);
    if (found == requests_.end() || found->second.descriptor != descriptor) {
        error = "requisição AIO inexistente ou descritor divergente";
        return false;
    }
    auto& request = found->second;
    switch (request.result.state) {
    case GuestAioState::Queued:
        request.result.state = GuestAioState::Cancelled;
        request.result.return_value = -1;
        request.result.error = Ps4Errno::Canceled;
        for (auto queued = queue_.begin(); queued != queue_.end();) {
            if (*queued == control_block) queued = queue_.erase(queued);
            else ++queued;
        }
        disposition = GuestAioCancelDisposition::Cancelled;
        changed_.notify_all();
        break;
    case GuestAioState::Running:
        disposition = GuestAioCancelDisposition::InProgress;
        break;
    case GuestAioState::Completed:
    case GuestAioState::Failed:
    case GuestAioState::Cancelled:
        disposition = GuestAioCancelDisposition::AlreadyComplete;
        break;
    }
    error.clear();
    return true;
}

bool GuestAioRuntime::cancel_descriptor(
    int descriptor, GuestAioCancelDisposition& disposition,
    std::vector<std::uint64_t>& cancelled, std::string& error) {
    if (descriptor < 0) {
        error = "descritor inválido para cancelamento AIO";
        return false;
    }
    const std::lock_guard lock(mutex_);
    bool running = false;
    bool active = false;
    cancelled.clear();
    for (auto& [control_block, request] : requests_) {
        if (request.descriptor != descriptor) continue;
        if (request.result.state == GuestAioState::Queued) {
            request.result.state = GuestAioState::Cancelled;
            request.result.return_value = -1;
            request.result.error = Ps4Errno::Canceled;
            cancelled.push_back(control_block);
            active = true;
        } else if (request.result.state == GuestAioState::Running) {
            running = true;
            active = true;
        }
    }
    if (active) {
        for (auto queued = queue_.begin(); queued != queue_.end();) {
            const auto found = requests_.find(*queued);
            if (found != requests_.end() && found->second.descriptor == descriptor &&
                found->second.result.state == GuestAioState::Cancelled) {
                queued = queue_.erase(queued);
            } else {
                ++queued;
            }
        }
    }
    disposition = running ? GuestAioCancelDisposition::InProgress
        : (active ? GuestAioCancelDisposition::Cancelled
                  : GuestAioCancelDisposition::AlreadyComplete);
    error.clear();
    if (!cancelled.empty()) changed_.notify_all();
    return true;
}

bool GuestAioRuntime::wait(std::span<const std::uint64_t> control_blocks,
                           bool wait_all,
                           std::optional<std::chrono::nanoseconds> timeout,
                           std::string& error) {
    if (control_blocks.empty()) {
        error = "a lista de blocos AIO está vazia";
        return false;
    }
    std::unique_lock lock(mutex_);
    for (const auto control_block : control_blocks) {
        if (!requests_.contains(control_block)) {
            error = "a lista contém um bloco de controle AIO desconhecido";
            return false;
        }
    }
    const auto ready = [this, control_blocks, wait_all] {
        std::size_t finished = 0;
        for (const auto control_block : control_blocks) {
            const auto found = requests_.find(control_block);
            if (found != requests_.end() && is_finished(found->second.result.state)) ++finished;
        }
        return wait_all ? finished == control_blocks.size() : finished != 0;
    };
    bool completed{};
    if (timeout) {
        completed = changed_.wait_for(lock, *timeout, ready);
    } else {
        changed_.wait(lock, ready);
        completed = true;
    }
    if (!completed) {
        error = "tempo limite aguardando requisições AIO";
        return false;
    }
    error.clear();
    return true;
}

bool GuestAioRuntime::wait_descriptor(
    int descriptor, std::optional<std::chrono::nanoseconds> timeout,
    std::string& error) {
    if (descriptor < 0) {
        error = "descritor inválido para barreira AIO";
        return false;
    }
    std::unique_lock lock(mutex_);
    const auto ready = [this, descriptor] {
        for (const auto& [control_block, request] : requests_) {
            (void)control_block;
            if (request.descriptor == descriptor && !is_finished(request.result.state)) return false;
        }
        return true;
    };
    bool completed{};
    if (timeout) {
        completed = changed_.wait_for(lock, *timeout, ready);
    } else {
        changed_.wait(lock, ready);
        completed = true;
    }
    if (!completed) {
        error = "tempo limite aguardando operações AIO do descritor";
        return false;
    }
    error.clear();
    return true;
}

std::optional<GuestAioSnapshot> GuestAioRuntime::snapshot(
    std::uint64_t control_block) const {
    const std::lock_guard lock(mutex_);
    const auto found = requests_.find(control_block);
    if (found == requests_.end()) return std::nullopt;
    return found->second.result;
}

bool GuestAioRuntime::forget(std::uint64_t control_block, std::string& error) {
    const std::lock_guard lock(mutex_);
    const auto found = requests_.find(control_block);
    if (found == requests_.end()) {
        error = "bloco de controle AIO desconhecido";
        return false;
    }
    if (!is_finished(found->second.result.state)) {
        error = "não é possível liberar uma requisição AIO ainda ativa";
        return false;
    }
    for (auto queued = queue_.begin(); queued != queue_.end();) {
        if (*queued == control_block) queued = queue_.erase(queued);
        else ++queued;
    }
    requests_.erase(found);
    error.clear();
    return true;
}

bool GuestAioRuntime::is_finished(GuestAioState state) noexcept {
    return state == GuestAioState::Completed || state == GuestAioState::Failed ||
           state == GuestAioState::Cancelled;
}

void GuestAioRuntime::worker_loop() noexcept {
    for (;;) {
        std::uint64_t control_block{};
        Work work;
        {
            std::unique_lock lock(mutex_);
            changed_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
            if (stopping_) return;
            control_block = queue_.front();
            queue_.pop_front();
            const auto found = requests_.find(control_block);
            if (found == requests_.end() || found->second.result.state != GuestAioState::Queued) {
                changed_.notify_all();
                continue;
            }
            found->second.result.state = GuestAioState::Running;
            work = found->second.work;
        }

        GuestAioCompletion completion{};
        try {
            completion = work();
        } catch (...) {
            completion.return_value = -1;
            completion.error = Ps4Errno::Io;
        }

        {
            const std::lock_guard lock(mutex_);
            const auto found = requests_.find(control_block);
            if (found != requests_.end() && found->second.result.state == GuestAioState::Running) {
                found->second.result.return_value = completion.return_value;
                found->second.result.error = completion.error;
                found->second.result.state = completion.error == Ps4Errno::Success
                    ? GuestAioState::Completed : GuestAioState::Failed;
            }
        }
        changed_.notify_all();
    }
}

} // namespace nba16
