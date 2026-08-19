#pragma once
#include <array>
#include <cstdint>
#include <span>
namespace prts { std::array<std::uint8_t,16> md5(std::span<const std::uint8_t> data); }
