cmake_minimum_required(VERSION 3.22.1)

project("veracrypt-native" LANGUAGES CXX)

option(VERACRYPT_ENABLE_SANITIZERS "Enable ASan and UBSan for native test builds" OFF)

# VeraCrypt header and read-only filesystem engine. Mutation entry points are
# deliberately absent until their separate roadmap acceptance gates pass.
add_library(
    veracrypt-native
    SHARED
    src/main/cpp/veracrypt_jni.cpp
    src/main/cpp/filesystem_validation.cpp
    src/main/cpp/secure_memory.cpp
)

find_library(log-lib log)

target_link_libraries(
    veracrypt-native
    ${log-lib}
)

target_compile_features(veracrypt-native PRIVATE cxx_std_17)

target_compile_options(
    veracrypt-native
    PRIVATE
    -Wall
    -Wextra
    -Werror
    -fstack-protector-strong
    -fvisibility=hidden
)

target_compile_definitions(veracrypt-native PRIVATE _FORTIFY_SOURCE=2)

if (VERACRYPT_ENABLE_SANITIZERS)
    target_compile_options(veracrypt-native PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(veracrypt-native PRIVATE -fsanitize=address,undefined)
endif()
