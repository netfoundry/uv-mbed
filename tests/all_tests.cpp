/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define CATCH_CONFIG_RUNNER

#include <uv_mbed/uv_mbed.h>
#include "catch.hpp"


static void test_log_f(const char* lvl, const char *file, unsigned int line, const char* msg){
    printf("[%7s] %s:%d\t%s\n", lvl, file, line, msg);
}

um_log_func test_log = test_log_f;

int main( int argc, char* argv[] ) {

    const char* debug = getenv("UM_TEST_DEBUG");
    if (debug) {
        // enable logging during tests
        long level = strtol(debug, NULL, 10);
        uv_mbed_set_debug((int)level, test_log);

    }
    int result = Catch::Session().run( argc, argv );

    return result;
}