#pragma once

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <random>
#include <string>
#include <vector>

namespace VulneraTextX::Fuzzing {
    class Input {
    public:
        Input();

        explicit Input(const std::vector<std::uint8_t>& data);
        explicit Input(std::vector<std::uint8_t>&& data);

        explicit Input(const std::string& data);

        Input(const uint8_t* data, std::size_t size);

        // Copy
        Input(const Input& other);
        Input& operator=(const Input& other);

        // Move
        Input(Input&& other) noexcept;
        Input& operator=(Input&& other) noexcept;

        ~Input();

        const uint8_t* data() const;

        std::size_t size() const;

        bool empty() const;

        // Ref to the internal vector
        const std::vector<std::uint8_t>& getVector() const;

        // Mutates input data using bit flip
        void mutate();

    protected:
    private:
        std::vector<std::uint8_t> m_data;

        static std::mt19937 s_randomEngine; // Random number generator
    };
} // namespace VulneraTextX::Fuzzing
