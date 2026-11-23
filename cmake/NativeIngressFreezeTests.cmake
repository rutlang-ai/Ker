if(BUILD_TESTING)
	target_sources(ker-posix-member-census-test-runtime PRIVATE
		"${PROJECT_SOURCE_DIR}/tests/posix/c24-ingress-freeze-test-runtime.c")
	target_include_directories(ker-posix-member-census-test-runtime PRIVATE
		"${PROJECT_SOURCE_DIR}/src/posix")
	file(READ "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
		ker_c24_ingress_freeze_export_map)
	string(REPLACE "ker_c15_admission_test_run;"
		"ker_c15_admission_test_run; ker_c24_ingress_freeze_test_run;"
		ker_c24_ingress_freeze_export_map "${ker_c24_ingress_freeze_export_map}")
	file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
		"${ker_c24_ingress_freeze_export_map}")
	file(READ "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
		ker_c28_race_export_map)
	string(REPLACE "ker_ff_admission_request_identity_test_parse; local: *;"
		"ker_ff_admission_request_identity_test_parse; ker_posix_ff_ingress_controller_test_registry_race; local: *;"
		ker_c28_race_export_map "${ker_c28_race_export_map}")
	file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/member-census-test-exports.map"
		"${ker_c28_race_export_map}")
	add_executable(ker-c24-ingress-freeze-tap-client
		"${PROJECT_SOURCE_DIR}/tests/posix/c24-ingress-freeze-tap-client.c")
	target_compile_features(ker-c24-ingress-freeze-tap-client PRIVATE c_std_11)
	target_compile_options(ker-c24-ingress-freeze-tap-client PRIVATE -Wall -Wextra -Werror)
	target_link_libraries(ker-c24-ingress-freeze-tap-client PRIVATE
		ker-posix-member-census-test-runtime)
	add_test(NAME native-c24-ingress-freeze-tap
		COMMAND "${Python3_EXECUTABLE}"
			"${PROJECT_SOURCE_DIR}/tests/posix/c24-ingress-freeze-tap-wire.py"
			--launcher "${PROJECT_SOURCE_DIR}/tools/ker-run.py"
			--library "$<TARGET_FILE:ker-posix-member-census-test-runtime>"
			--worker "$<TARGET_FILE:ker-io-worker>"
			--dpdk-plugin-dir "${ker_session_pmd_dir}"
			--client "$<TARGET_FILE:ker-c24-ingress-freeze-tap-client>")
	set_tests_properties(native-c24-ingress-freeze-tap PROPERTIES
		TIMEOUT 120 LABELS "native-tcp;ingress-freeze;original-linux;tap;wire"
		ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

	add_executable(ker-ff-ingress-freeze-state-test
		"${PROJECT_SOURCE_DIR}/tests/posix/ff-ingress-freeze-state-test.c"
		"${PROJECT_SOURCE_DIR}/src/posix/ff-ingress-freeze-state.c")
	target_include_directories(ker-ff-ingress-freeze-state-test PRIVATE
		"${PROJECT_SOURCE_DIR}/src/posix")
	target_compile_features(ker-ff-ingress-freeze-state-test PRIVATE c_std_11)
	target_compile_options(ker-ff-ingress-freeze-state-test PRIVATE
		-Wall -Wextra -Werror)
	add_test(NAME ff-ingress-freeze-state
		COMMAND "$<TARGET_FILE:ker-ff-ingress-freeze-state-test>")
	set_tests_properties(ff-ingress-freeze-state PROPERTIES
		TIMEOUT 10 LABELS "native-tcp;ingress-freeze;state")

	add_executable(ker-ff-ingress-freeze-parser-test
		"${PROJECT_SOURCE_DIR}/tests/posix/ff-ingress-freeze-parser-test.c"
		"${PROJECT_SOURCE_DIR}/src/posix/ff-ingress-freeze-queue-parse.c")
	target_include_directories(ker-ff-ingress-freeze-parser-test PRIVATE
		"${PROJECT_SOURCE_DIR}/src/posix")
	target_include_directories(ker-ff-ingress-freeze-parser-test SYSTEM PRIVATE
		"${ker_native_source}/tools/lkl/include" "${ker_native_tools}/include")
	target_compile_features(ker-ff-ingress-freeze-parser-test PRIVATE c_std_11)
	target_compile_options(ker-ff-ingress-freeze-parser-test PRIVATE
		-Wall -Wextra -Werror)
	add_test(NAME ff-ingress-freeze-parser
		COMMAND "$<TARGET_FILE:ker-ff-ingress-freeze-parser-test>")
	set_tests_properties(ff-ingress-freeze-parser PROPERTIES
		TIMEOUT 10 LABELS "native-tcp;ingress-freeze;parser")
endif()
