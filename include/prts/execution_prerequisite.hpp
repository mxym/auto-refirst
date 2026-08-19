#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <vector>
namespace prts {
std::vector<Finding> detect_execution_prerequisites(std::span<const std::uint8_t> data,const PeInfo& pe);
}
