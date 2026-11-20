add_executable(ker-zc-validation-test tests/posix/zc-validation.c)
target_include_directories(ker-zc-validation-test PRIVATE "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(ker-zc-validation-test PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
target_compile_options(ker-zc-validation-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME native-fstack-zc-validation
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/posix/zc-validation.py"
        --launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py" --library "$<TARGET_FILE:ker-posix>"
        --worker "$<TARGET_FILE:ker-io-worker>" --app "$<TARGET_FILE:ker-zc-validation-test>")
set_tests_properties(native-fstack-zc-validation PROPERTIES TIMEOUT 60 LABELS "fstack;native-dpdk")

foreach(fixture resize segments)
    add_executable(ker-native-buffer-${fixture}-test tests/posix/native-buffer-${fixture}.c
        src/posix/native-buffer.c src/posix/host-memory.c src/posix/host-clock.c)
    target_include_directories(ker-native-buffer-${fixture}-test PRIVATE
        "${PROJECT_SOURCE_DIR}/include" "${PROJECT_SOURCE_DIR}/src/posix")
    target_include_directories(ker-native-buffer-${fixture}-test SYSTEM PRIVATE
        "${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
    target_link_libraries(ker-native-buffer-${fixture}-test PRIVATE
        "${ker_native_tools}/liblkl.a" Threads::Threads ${CMAKE_DL_LIBS} rt)
    target_link_options(ker-native-buffer-${fixture}-test PRIVATE -Wl,--wrap=lkl_syscall)
    target_compile_options(ker-native-buffer-${fixture}-test PRIVATE -Wall -Wextra -Werror)
endforeach()
target_link_options(ker-native-buffer-segments-test PRIVATE -Wl,--wrap=malloc)
add_test(NAME native-fstack-buffer-resize COMMAND ker-native-buffer-resize-test)
add_test(NAME native-fstack-buffer-segments-layout COMMAND ker-native-buffer-segments-test layout)
add_test(NAME native-fstack-buffer-segments-failures COMMAND ker-native-buffer-segments-test failures)
set_tests_properties(native-fstack-buffer-resize native-fstack-buffer-segments-layout native-fstack-buffer-segments-failures
    PROPERTIES TIMEOUT 35 LABELS fstack)
