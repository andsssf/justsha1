add_executable(justsha1_test test.cpp)
target_link_libraries(justsha1_test justsha1)
add_test(NAME Test1 COMMAND justsha1_test string_test)
set_tests_properties(Test1 PROPERTIES PASS_REGULAR_EXPRESSION "76d382d611d2ec35c23d86a022e43aea0820ef8e")
add_test(NAME Test2 COMMAND justsha1_test file_test)
set_tests_properties(Test2 PROPERTIES PASS_REGULAR_EXPRESSION "4d8690bf2c5b483336f291fee1cad1f4d7c4d848")