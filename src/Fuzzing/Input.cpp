#include <algorithm>
#include <iterator>

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
} // namespace VulneraTextX::Fuzzing
