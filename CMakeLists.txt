CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

PROJECT("uv-mbed"
        LANGUAGES C
        VERSION 0.5.0
        )

#sample is off by default
option(ENABLE_SAMPLES "Build samples." OFF)

#
# which TLS engine to use (mbedTLS is currently the default)
#
option(ENABLE_MBEDTLS "Use mbedTLS engine." ON)
option(ENABLE_OPENSSL "Use OpenSSL engine." OFF)


add_subdirectory(deps)

# ----------------------------------------------------------
###     mbedTLS engine is enabled
# ----------------------------------------------------------
if (ENABLE_MBEDTLS)
set(uv_mbed_sources
        src/uv_mbed.c
        src/bio.c
        src/engine_mbedtls.c
        )

set(p11_sources
        src/p11/p11_mbedtls/mbed_p11.c
        src/p11/p11_mbedtls/p11_ecdsa.c
        src/p11/p11_mbedtls/p11_rsa.c)

# ----------------------------------------------------------
###     OpenSSL engine is enabled
# ----------------------------------------------------------
elseif (ENABLE_OPENSSL)
add_definitions(-DENABLE_OPENSSL)
set(uv_mbed_sources
        src/uv_mbed.c
        src/bio.c
        src/engine_openssl.c
        )

set(p11_sources
#        src/p11/p11_mbedtls/mbed_p11.c
#        src/p11/p11_mbedtls/p11_ecdsa.c
#        src/p11/p11_mbedtls/p11_rsa.c
        )
else()
message(FATAL_ERROR "no TLS engine was chosen")
endif()


# ----------------------------------------------------------
###     mbedTLS engine is enabled
# ----------------------------------------------------------
if (ENABLE_MBEDTLS)
add_library(uv_mbed SHARED
        ${uv_mbed_sources}
        ${p11_sources}
        )
# ----------------------------------------------------------
###     OpenSSL engine is enabled
# ----------------------------------------------------------
elseif (ENABLE_OPENSSL)
add_library(uv_mbed SHARED 
        ${uv_mbed_sources}
        ${p11_sources}
        )

add_library(ssl SHARED IMPORTED)
set_target_properties(ssl PROPERTIES
  IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl/libssl.dylib"
)
add_library(crypto SHARED IMPORTED)
set_target_properties(crypto PROPERTIES
  IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl/libcrypto.dylib"
)
else()
message(FATAL_ERROR "no TLS engine was chosen")
endif()


if (WIN32)
    target_include_directories(uv_mbed PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/win32/include)
endif()

if (ENABLE_OPENSSL)
    target_include_directories(uv_mbed PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl/include)
endif()

target_include_directories(uv_mbed
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/p11
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/libuv/src
        )

# ----------------------------------------------------------
###     mbedTLS engine is enabled
# ----------------------------------------------------------
if (ENABLE_MBEDTLS)
target_link_libraries(uv_mbed
        PUBLIC uv_a
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto)

# ----------------------------------------------------------
###     OpenSSL engine is enabled
# ----------------------------------------------------------
elseif (ENABLE_OPENSSL)
target_link_libraries(uv_mbed
        PUBLIC uv_a
        ssl
        crypto
        )
else()
message(FATAL_ERROR "no TLS engine was chosen")
endif()


install(DIRECTORY include/uv_mbed DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS uv_mbed
        ARCHIVE DESTINATION lib)

if(ENABLE_SAMPLES)
add_subdirectory(sample)
endif()