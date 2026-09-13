cmake_minimum_required(VERSION 3.21)
project(agentdns_ccf LANGUAGES C CXX)
find_package(ccf 7.0.15 EXACT REQUIRED HINTS /opt/ccf)
get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(RUST_TARGET_DIR "${CMAKE_BINARY_DIR}/cargo" CACHE PATH "Isolated Rust artifacts")
set(RUST_ARCHIVE "${RUST_TARGET_DIR}/release/libadns_ccf.a")
set(RUST_SUPPORT_HEADER "${RUST_TARGET_DIR}/support/rust/cxx.h")
file(GLOB_RECURSE RUST_SOURCES CONFIGURE_DEPENDS "${REPO_ROOT}/crates/*.rs" "${REPO_ROOT}/crates/*.toml" "${REPO_ROOT}/crates/adns-ccf/*.cpp" "${REPO_ROOT}/crates/adns-ccf/*.h")
add_custom_command(OUTPUT "${RUST_ARCHIVE}" "${RUST_SUPPORT_HEADER}"
  COMMAND ${CMAKE_COMMAND} -E env "CCF_INCLUDE_DIR=${CCF_DIR}/include" "CARGO_TARGET_DIR=${RUST_TARGET_DIR}" "CXX=${CMAKE_CXX_COMPILER}" "CC=${CMAKE_C_COMPILER}" cargo build --locked --release -p adns-ccf --features ccf
  # Cargo's generated rust/cxx.h is a symlink into the invoking container's
  # registry cache. Preserve a real copy so incremental C++ builds in another
  # disposable toolchain container do not depend on that vanished cache.
  COMMAND ${CMAKE_COMMAND} -E make_directory "${RUST_TARGET_DIR}/support/rust"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${RUST_TARGET_DIR}/cxxbridge/rust/cxx.h" "${RUST_SUPPORT_HEADER}"
  WORKING_DIRECTORY "${REPO_ROOT}"
  DEPENDS ${RUST_SOURCES} "${REPO_ROOT}/Cargo.toml" "${REPO_ROOT}/Cargo.lock"
  VERBATIM)
add_custom_target(agentdns_rust DEPENDS "${RUST_ARCHIVE}" "${RUST_SUPPORT_HEADER}")
# CCF's release SDK and our staticlib embed independent Rust std runtimes.
# Keep both complete implementations; namespace the SDK's sole unmangled EH
# personality and every reference to it in an isolated archive copy.
set(SDK_RUST_ARCHIVE "${CMAKE_BINARY_DIR}/libccf_rs_namespaced.a")
add_custom_command(OUTPUT "${SDK_RUST_ARCHIVE}"
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/namespace_rust_runtime.py" "${CCF_DIR}/lib/libccf_rs.a" "${SDK_RUST_ARCHIVE}"
  DEPENDS "${CCF_DIR}/lib/libccf_rs.a" "${CMAKE_CURRENT_SOURCE_DIR}/namespace_rust_runtime.py"
  VERBATIM)
add_custom_target(agentdns_sdk_rust DEPENDS "${SDK_RUST_ARCHIVE}")
get_target_property(CCF_CRYPTO_LINKS ccfcrypto INTERFACE_LINK_LIBRARIES)
list(TRANSFORM CCF_CRYPTO_LINKS REPLACE "^${CCF_DIR}/lib/libccf_rs\\.a$" "${SDK_RUST_ARCHIVE}")
set_property(TARGET ccfcrypto PROPERTY INTERFACE_LINK_LIBRARIES "${CCF_CRYPTO_LINKS}")

add_ccf_app(agentdns SRCS app.cpp main.cpp telemetry.cpp
  INCLUDE_DIRS "${RUST_TARGET_DIR}/support" "${RUST_TARGET_DIR}/cxxbridge" "${REPO_ROOT}/crates/adns-ccf/include"
  LINK_LIBS "${RUST_ARCHIVE}" pthread dl m
  DEPS agentdns_rust agentdns_sdk_rust)
set_property(TARGET agentdns PROPERTY CXX_STANDARD 23)
install(TARGETS agentdns DESTINATION bin)
