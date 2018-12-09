############################# INITIAL SECTION #############################################
cmake_minimum_required(VERSION 2.8.0 FATAL_ERROR)

project(hpenc CXX)
set(HPENC_VERSION "3.0")

macro(use_cxx11)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_CXX_FLAGS "--std=gnu++11 ${CMAKE_CXX_FLAGS}")
    else ()
      set (CMAKE_CXX_FLAGS "--std=c++11 ${CMAKE_CXX_FLAGS}")
    endif ()
  else ()
    set (CMAKE_CXX_STANDARD 11)
  endif ()
endmacro(use_cxx11)

use_cxx11()
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
find_package(sodium REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
include_directories("${OPENSSL_INCLUDE_DIR}")
include_directories("${sodium_INCLUDE_DIR}")
list(APPEND LIBS "${sodium_LIBRARY_RELEASE}")
list(APPEND LIBS "${OPENSSL_LIBRARIES}")
set(SOURCES "src/aead.cc"
	"src/decrypt.cc"
	"src/encrypt.cc"
	"src/kdf.cc"
	"src/main.cc"
	"src/nonce.cc"
	"src/util.cc")
add_executable(hpenc ${SOURCES})

target_link_libraries(hpenc ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(hpenc ${LIBS})
set_target_properties(hpenc PROPERTIES VERSION ${HPENC_VERSION})
install(TARGETS hpenc DESTINATION bin)
