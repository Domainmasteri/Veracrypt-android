cmake_minimum_required(VERSION 3.22.1)

project("veracrypt-native" LANGUAGES CXX)

# VeraCrypt JNI bridge — read-only container header parsing stub.
# Real cryptographic implementation will be added in a subsequent milestone.
add_library(
    veracrypt-native
    SHARED
    src/main/cpp/veracrypt_jni.cpp
)

find_library(log-lib log)

target_link_libraries(
    veracrypt-native
    ${log-lib}
)

target_compile_features(veracrypt-native PRIVATE cxx_std_17)
