find_package(SEAL 4.1 REQUIRED)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(sealpir bloom_filter.hpp pir.hpp pir.cpp pir_client.hpp pir_client.cpp pir_server.hpp
  pir_server.cpp)
target_link_libraries(sealpir SEAL::seal)

add_executable(main main.cpp)
target_link_libraries(main sealpir)
