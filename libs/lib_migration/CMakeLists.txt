cmake_minimum_required(VERSION 3.10)
project(lib_migration)

set(CMAKE_CXX_STANDARD 11)

include_directories(generated)
include_directories(trusted)

add_executable(lib_migration
        generated/lib_migration_t.c
        generated/lib_migration_t.h
        generated/lib_migration_u.c
        generated/lib_migration_u.h
        trusted/marshalling.cpp
        trusted/marshalling.h
        trusted/migration_counters.cpp
        trusted/migration_library.cpp
        trusted/migration_library.h
        trusted/migration_library_internal.cpp
        trusted/migration_library_internal.h
        trusted/migration_seal.cpp)

include_directories(/opt/intel/sgxsdk/include)
