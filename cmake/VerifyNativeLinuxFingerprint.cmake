function(ker_verify_native_linux_fingerprint source_root manifest_path builder_script)
    set(config_fragment "")
    if(ARGC GREATER 3)
        set(config_fragment "${ARGV3}")
    endif()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${source_root}/config/native-linux.json"
        "${source_root}/config/native-linux.defconfig"
        "${manifest_path}"
        "${builder_script}")
    if(config_fragment)
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
            "${source_root}/${config_fragment}")
        get_filename_component(ker_config_directory "${config_fragment}" DIRECTORY)
        get_filename_component(ker_config_name "${config_fragment}" NAME)
        string(REGEX REPLACE "\\.[^.]*$" "" ker_config_name "${ker_config_name}")
        set(ker_config_prelude "${source_root}/${ker_config_directory}/${ker_config_name}.Kconfig")
        if(EXISTS "${ker_config_prelude}")
            set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${ker_config_prelude}")
        endif()
    endif()
    file(GLOB_RECURSE ker_native_overlay_files CONFIGURE_DEPENDS
        LIST_DIRECTORIES FALSE "${source_root}/src/posix/lkl-overlay/*")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${ker_native_overlay_files})

    set(ker_fingerprint_arguments --print-fingerprint --fingerprint-root "${source_root}")
    if(config_fragment)
        list(APPEND ker_fingerprint_arguments --config-fragment "${config_fragment}")
    endif()
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" "${builder_script}" ${ker_fingerprint_arguments}
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
