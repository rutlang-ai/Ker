function(ker_verify_native_linux_fingerprint source_root manifest_path builder_script)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${source_root}/config/native-linux.json"
        "${source_root}/config/native-linux.defconfig"
        "${manifest_path}"
        "${builder_script}")
    file(GLOB_RECURSE ker_native_overlay_files CONFIGURE_DEPENDS
        LIST_DIRECTORIES FALSE "${source_root}/src/posix/lkl-overlay/*")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${ker_native_overlay_files})

    execute_process(
        COMMAND "${Python3_EXECUTABLE}" "${builder_script}"
            --print-fingerprint --fingerprint-root "${source_root}"
        RESULT_VARIABLE ker_fingerprint_result
        OUTPUT_VARIABLE ker_current_fingerprint
        ERROR_VARIABLE ker_fingerprint_error
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT ker_fingerprint_result EQUAL 0)
        message(FATAL_ERROR "Cannot calculate native Linux source fingerprint: ${ker_fingerprint_error}")
    endif()
    file(READ "${manifest_path}" ker_native_manifest_json)
    string(JSON ker_expected_fingerprint GET "${ker_native_manifest_json}" fingerprint)
    if(NOT ker_current_fingerprint STREQUAL ker_expected_fingerprint)
        message(FATAL_ERROR "Native Linux source inputs differ from the artifact fingerprint; rerun tools/build-native-linux.py")
    endif()
endfunction()
