cmake_minimum_required(VERSION 2.8)
project(newspeed)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "~/.cmake/Modules")
set(CMAKE_VERBOSE_MAKEFILE ON)

find_package(OpenSSL REQUIRED)
message("OpenSSL root dir: ${OPENSSL_ROOT_DIR}")
message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
include_directories(${OPENSSL_INCLUDE_DIR})

option(NO_EVP_DIGESTSIGN "Forcefully disable support for EVP_DigestSign and EVP_DigestVerify" OFF)

file(GLOB SOURCES "src/*.c")
add_executable(newspeed ${SOURCES})
target_link_libraries(newspeed ${OPENSSL_LIBRARIES})

IF(NO_EVP_DIGESTSIGN)
	target_compile_definitions(newspeed PRIVATE NO_EVP_DIGESTSIGN)
ENDIF()

set_target_properties(newspeed PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)

target_compile_definitions(newspeed PRIVATE _DEBUG)
target_compile_definitions(newspeed PRIVATE DEBUG_COLORS)

#target_compile_options(newspeed PRIVATE "-O0")
target_link_libraries(newspeed ${OPENSSL_LIBRARIES})
target_link_libraries(newspeed m)
set_target_properties(newspeed PROPERTIES COMPILE_FLAGS "-Werror=implicit-function-declaration")
set_target_properties(newspeed PROPERTIES C_STANDARD 99)

if(${OPENSSL_VERSION} VERSION_LESS 1.1.0)
	#set_target_properties(newspeed PROPERTIES COMPILE_FLAGS "-Werror=implicit-function-declaration -Wno-incompatible-pointer-types -Wno-discarded-qualifiers")
	set_target_properties(newspeed PROPERTIES COMPILE_FLAGS "-Werror=implicit-function-declaration -Wno-discarded-qualifiers")

	target_compile_definitions(newspeed PRIVATE OPENSSL_V102_COMPAT)
endif(${OPENSSL_VERSION} VERSION_LESS 1.1.0)

install(TARGETS newspeed
		RUNTIME DESTINATION bin)


