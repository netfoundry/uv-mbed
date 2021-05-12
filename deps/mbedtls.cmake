include(FetchContent)
FetchContent_Declare(mbedtls
        GIT_REPOSITORY https://github.com/netfoundry/mbedtls.git
        GIT_TAG verify-ip-sans+gcc11+mingw-stdio_2.x
        GIT_SHALLOW 1
)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mbedtls)
