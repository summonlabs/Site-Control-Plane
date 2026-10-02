// Site Control Plane - DCCP
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "scp/version.hpp"

namespace scp {

namespace {

/// The literal is the published identity of this build. The assertion keeps it
/// in step with the numeric constants, so bumping a constant without updating
/// the string is a compile error rather than a release that lies about itself.
constexpr char kVersionString[] = "1.0.0";

static_assert(kVersionMajor == 1 && kVersionMinor == 0 && kVersionPatch == 0,
              "version_string() must be updated together with the version constants");

}  // namespace

std::string_view version_string() noexcept { return kVersionString; }

}  // namespace scp
