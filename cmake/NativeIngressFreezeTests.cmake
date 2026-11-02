if(BUILD_TESTING)
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
