cmake_minimum_required(VERSION 3.22)
project(veracrypt_filesystem_fuzzers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(filesystem_validation STATIC
    ../src/main/cpp/filesystem_validation.cpp
)
target_include_directories(filesystem_validation PUBLIC ../src/main/cpp)
target_compile_options(filesystem_validation PRIVATE
    -Wall -Wextra -Werror -fno-omit-frame-pointer
    -fsanitize=address,undefined,fuzzer-no-link
)

function(add_validation_fuzzer target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE filesystem_validation)
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Werror -fno-omit-frame-pointer
        -fsanitize=address,undefined,fuzzer
    )
    target_link_options(${target} PRIVATE
        -fsanitize=address,undefined,fuzzer
    )
endfunction()

add_validation_fuzzer(bpb_fuzzer bpb_fuzzer.cpp)
add_validation_fuzzer(fat_fuzzer fat_fuzzer.cpp)
add_validation_fuzzer(directory_fuzzer directory_fuzzer.cpp)

add_executable(validation_regression_test validation_regression_test.cpp)
target_link_libraries(validation_regression_test PRIVATE filesystem_validation)
target_compile_options(validation_regression_test PRIVATE
    -Wall -Wextra -Werror -fno-omit-frame-pointer
    -fsanitize=address,undefined
)
target_link_options(validation_regression_test PRIVATE -fsanitize=address,undefined)
enable_testing()
add_test(NAME validation_regression_test COMMAND validation_regression_test)
