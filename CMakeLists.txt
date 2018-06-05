cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

project(caman VERSION 0.1.0 LANGUAGES CXX)

# Options
#nothing to see here... yet

add_executable(${PROJECT_NAME} caman.cpp)
set_target_properties(${PROJECT_NAME}
	PROPERTIES
		CXX_STANDARD_REQUIRED ON
		CXX_EXTENSIONS OFF
)
target_compile_features(${PROJECT_NAME} PUBLIC "cxx_std_17")
target_include_directories(${PROJECT_NAME} PUBLIC /usr/include/botan-2)
target_link_libraries(${PROJECT_NAME} PUBLIC stdc++fs botan-2)
