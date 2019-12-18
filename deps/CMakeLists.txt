set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)

if (ENABLE_MBEDTLS)
add_subdirectory(mbedtls)
elseif (ENABLE_OPENSSL)
#add_subdirectory(openssl)
else()
message(FATAL_ERROR "no TLS engine was chosen")
endif()

if (ENABLE_MBEDTLS)
set_target_properties(mbedtls PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/mbedtls/include)
elseif (ENABLE_OPENSSL)
#target_include_directories(uv_mbed PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include)
else()
message(FATAL_ERROR "no TLS engine was chosen")
endif()


set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
add_subdirectory(libuv)
set_target_properties(uv_a PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libuv/include)