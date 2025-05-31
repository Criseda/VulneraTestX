#include <algorithm>
#include <chrono>
#include <iterator>
#include <random>

#include <Fuzzing/Input.hpp>

namespace VulneraTextX::Fuzzing {
    Input::Input() : m_data() {}

    Input::Input(const std::vector<std::uint8_t>& data) : m_data(data) {}

    Input::Input(std::vector<std::uint8_t>&& data) : m_data(std::move(data)) {}

    Input::Input(const std::string& data) : m_data(data.begin(), data.end()) {}

    Input::Input(const uint8_t* data, std::size_t size) {
        if (data && size > 0) {
            m_data.assign(data, data + size);
        } else {
            m_data.clear();
        }
    }

    Input::Input(const Input& other) : m_data(other.m_data) {}

    Input& Input::operator=(const Input& other) {
        if (this != &other) {
            m_data = other.m_data;
        }
        return *this;
    }

    Input::Input(Input&& other) noexcept : m_data(std::move(other.m_data)) {}

    Input& Input::operator=(Input&& other) noexcept {
        if (this != &other) {
            m_data = std::move(other.m_data);
        }
        return *this;
    }

    Input::~Input() = default;

    const uint8_t* Input::data() const {
        if (m_data.empty()) {
            static const uint8_t empty_sentinel = 0;
            return &empty_sentinel; // Return a pointer to a static sentinel value if empty
        }
        return m_data.data();
    }

    std::size_t Input::size() const {
        return m_data.size();
    }

    bool Input::empty() const {
        return m_data.empty();
    }

    const std::vector<std::uint8_t>& Input::getVector() const {
        return m_data;
    }

    // Mutate implementation
    void Input::mutate() {
        if (m_data.empty()) {
            return;
        }

        // Thread-Local Random Engine
        static thread_local std::mt19937 s_randomEngine(
            static_cast<unsigned int>(std::chrono::steady_clock::now().time_since_epoch().count()));

        // Select random byte
        std::uniform_int_distribution<size_t> byte_dist(0, m_data.size() - 1);
        size_t byte_idx = byte_dist(s_randomEngine);

        // Select random bit in byte_idx
        std::uniform_int_distribution<int> bit_dist(0, 7);
        int bit_idx = bit_dist(s_randomEngine);

        // Flip bit
        m_data[byte_idx] ^= (1 << bit_idx);
    }
} // namespace VulneraTextX::Fuzzing
