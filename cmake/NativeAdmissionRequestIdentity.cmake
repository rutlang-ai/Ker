# Included after the native POSIX targets and C14 request-revoke target.
if(BUILD_TESTING)
	add_executable(ker-ff-admission-request-identity-parser-test
		"${PROJECT_SOURCE_DIR}/tests/posix/ff-admission-request-identity-parser.c")
	target_include_directories(ker-ff-admission-request-identity-parser-test PRIVATE
		"${PROJECT_SOURCE_DIR}/src/posix" "${PROJECT_SOURCE_DIR}/include")
	target_include_directories(ker-ff-admission-request-identity-parser-test SYSTEM PRIVATE
		"${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
	target_sources(ker-ff-admission-request-identity-parser-test PRIVATE
		"${PROJECT_SOURCE_DIR}/src/posix/ff-admission-request-identity.c")
	target_compile_definitions(ker-ff-admission-request-identity-parser-test PRIVATE
		KER_FF_ADMISSION_REQUEST_IDENTITY_TESTING)
	target_compile_features(ker-ff-admission-request-identity-parser-test PRIVATE c_std_11)
	target_compile_options(ker-ff-admission-request-identity-parser-test PRIVATE
		-Wall -Wextra -Werror -ffunction-sections -fdata-sections)
	target_link_options(ker-ff-admission-request-identity-parser-test PRIVATE
		-Wl,--gc-sections)
	add_test(NAME ff-admission-request-identity-parser
		COMMAND "$<TARGET_FILE:ker-ff-admission-request-identity-parser-test>")
	set_tests_properties(ff-admission-request-identity-parser PROPERTIES
		TIMEOUT 10 LABELS "native-tcp;admission;parser")

	add_executable(ker-ff-admission-request-identity-runtime-test
		"${PROJECT_SOURCE_DIR}/tests/posix/ff-admission-request-identity-runtime.c")
	target_include_directories(ker-ff-admission-request-identity-runtime-test PRIVATE
		"${PROJECT_SOURCE_DIR}/src/posix" "${PROJECT_SOURCE_DIR}/include")
	target_compile_features(ker-ff-admission-request-identity-runtime-test PRIVATE c_std_11)
	target_compile_options(ker-ff-admission-request-identity-runtime-test PRIVATE
		-Wall -Wextra -Werror)
	target_link_libraries(ker-ff-admission-request-identity-runtime-test PRIVATE
		ker-posix-member-census-test-runtime)
	add_dependencies(ker-ff-admission-request-identity-runtime-test ker-app ker-io-worker)
	add_test(NAME native-ff-admission-request-identity-wire
		COMMAND "${Python3_EXECUTABLE}"
			"${PROJECT_SOURCE_DIR}/tests/posix/ff-admission-request-identity-wire.py"
			--launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
			--library "$<TARGET_FILE:ker-posix-member-census-test-runtime>"
			--worker "$<TARGET_FILE:ker-io-worker>"
			--dpdk-plugin-dir "${ker_session_pmd_dir}"
			--client "$<TARGET_FILE:ker-ff-admission-request-identity-runtime-test>")
	set_tests_properties(native-ff-admission-request-identity-wire PROPERTIES
		TIMEOUT 120 LABELS "native-tcp;admission;original-linux"
		ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

	target_sources(ker-posix-member-census-test-runtime PRIVATE
		"${PROJECT_SOURCE_DIR}/src/posix/ff-admission-request-identity.c")
	target_compile_definitions(ker-posix-member-census-test-runtime PRIVATE
		KER_FF_ADMISSION_REQUEST_IDENTITY_TESTING)
	file(READ "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
		ker_c15_identity_test_export_map)
	string(REPLACE "ker_c15_admission_test_run; local: *;"
		"ker_c15_admission_test_run; ker_ff_admission_request_identity_begin; ker_ff_admission_request_identity_step; ker_ff_admission_request_identity_revalidate; ker_ff_admission_request_identity_close; ker_ff_admission_request_identity_test_parse; local: *;"
		ker_c15_identity_test_export_map "${ker_c15_identity_test_export_map}")
	file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
		"${ker_c15_identity_test_export_map}")
endif()
