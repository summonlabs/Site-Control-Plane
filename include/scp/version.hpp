// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string_view>

/// \file version.hpp
/// Build and format identity of the Site Control Plane runtime.

namespace scp {

/// Semantic version of the library, tool and package.
inline constexpr std::uint32_t kVersionMajor = 1;
inline constexpr std::uint32_t kVersionMinor = 0;
inline constexpr std::uint32_t kVersionPatch = 0;

/// \return "1.0.0".
[[nodiscard]] std::string_view version_string() noexcept;

/// Version of the on-disk journal and snapshot framing this build writes and is
/// able to read. A build refuses a container written by a newer major format.
inline constexpr std::uint32_t kFormatVersion = 1;

/// Version of the evidence body schemas this build understands. Evidence whose
/// schema is unknown is preserved and reported as unsupported, never guessed at.
inline constexpr std::uint16_t kEvidenceSchemaVersion = 1;

}  // namespace scp
