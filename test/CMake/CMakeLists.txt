cmake_minimum_required (VERSION 3.5.1)

# Create the signature project
project(PALISADEsignatureTest CXX)

# Use C++11 standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Palisade 1.11.0 REQUIRED)

set( CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS} )
set( CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${PALISADE_INCLUDE} )
include_directories( ${PALISADE_INCLUDE}/third-party/include )
include_directories( ${PALISADE_INCLUDE}/core )
include_directories( ${PALISADE_INCLUDE}/pke )

link_directories( ${PALISADE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )

link_libraries( ${PALISADE_SHARED_LIBRARIES} )

find_package(PALISADEsignature 1.11.0 REQUIRED)

if (PALISADEsignature_FOUND)
  message(NOTICE "Libraries for mypackage found")
  message(NOTICE "Package Version: " ${PALISADEsignature_VERSION})
else()
  message(FATAL_ERROR "Failed to find mypackage.")
endif()

include_directories( ${SIGNATURE_INCLUDE} )
link_directories( ${SIGNATURE_LIBDIR} )
link_libraries( ${SIGNATURE_SHARED_LIBRARIES} )

message(NOTICE "SIGNATURE_INCLUDE: " ${SIGNATURE_INCLUDE})
message(NOTICE "SIGNATURE_LIBRARIES: " ${SIGNATURE_LIBRARIES})
message(NOTICE "SIGNATURE_SHARED_LIBRARIES: " ${SIGNATURE_SHARED_LIBRARIES})

##########################################################
### now build all files in examples and put executables in bin/signature/examples
##########################################################
#for all src files in examples directory
file (GLOB SIGNATURE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS ../../src/signature/examples/*.cpp)
foreach (app ${SIGNATURE_EXAMPLES_SRC_FILES})
  get_filename_component ( exe ${app} NAME_WE )
  add_executable ( ${exe} ${app} )
  set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/)
endforeach()
