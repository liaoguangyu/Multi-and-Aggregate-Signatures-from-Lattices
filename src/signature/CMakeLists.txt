#
# CMakeLists.txt for PALISADEsignature library
#

#list all sources in this directory for the library (found in the lib subdirectory)
file(GLOB SIGNATURE_SRC_FILES CONFIGURE_DEPENDS "lib/*-impl.cpp")

include_directories(${CORE_INCLUDE_DIRS})
include_directories(${PKE_INCLUDE_DIRS})
list(APPEND SIGNATURE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
list(APPEND SIGNATURE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/lib")
include_directories(${SIGNATURE_INCLUDE_DIRS})

add_library (signatureobj OBJECT ${SIGNATURE_SRC_FILES})
add_dependencies(signatureobj PALISADEcore)
set_property(TARGET signatureobj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(PALISADEsignature SHARED ${SIGNATURE_SRC_FILES})
set_property(TARGET PALISADEsignature PROPERTY VERSION ${SIGNATURE_VERSION})
set_property(TARGET PALISADEsignature PROPERTY SOVERSION ${SIGNATURE_VERSION_MAJOR})
set_property(TARGET PALISADEsignature PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

install(
	TARGETS PALISADEsignature 
	EXPORT PALISADEsignatureTargets 
	DESTINATION lib)
install(
	DIRECTORY include/
	DESTINATION include/palisade-signature)

set (SIGNATURELIBS PUBLIC PALISADEsignature PALISADEcore ${PALISADE_LIBRARIES})

target_link_libraries (PALISADEsignature ${PALISADE_LIBRARIES})

add_custom_target( allsignature )
add_dependencies( allsignature PALISADEsignature)

##########################################################
### now build all files in examples and put executables in bin/signature/examples
##########################################################

set (SIGNATUREAPPS "")
if( BUILD_EXAMPLES ) #set during cmake with -D
  #for all src files in examples directory
  file (GLOB SIGNATURE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
  foreach (app ${SIGNATURE_EXAMPLES_SRC_FILES})
	get_filename_component ( exe ${app} NAME_WE )
	add_executable ( ${exe} ${app} )
	##this is out output directory under build
	set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/signature)
	set( SIGNATUREAPPS ${SIGNATUREAPPS} ${exe} ) ##append this apname
	target_link_libraries ( ${exe} ${SIGNATURELIBS} )
  endforeach()
  
  add_custom_target( allsignatureexamples ) #new make target
  add_dependencies( allsignatureexamples ${SIGNATUREAPPS} ) #builds all example apps
  add_dependencies( allsignature allsignatureexamples ) 
endif()

##########################################################
### now build unittests
##########################################################

if( BUILD_UNITTESTS )
	set(UNITTESTMAIN ${PROJECT_SOURCE_DIR}/test/Main_TestAll.cpp)

  file (GLOB SIGNATURE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
	add_executable (signature_tests ${SIGNATURE_TEST_SRC_FILES} ${UNITTESTMAIN})
	set_property(TARGET signature_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
	target_link_libraries ( signature_tests ${SIGNATURELIBS} )
	if (NOT ${USE_OpenMP} )
		target_link_libraries ( signature_tests PRIVATE Threads::Threads)
	endif()
	add_dependencies( allsignature signature_tests )

	add_custom_command( OUTPUT runsignaturetests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/signature_tests )
	add_custom_target( testsignature DEPENDS signature_tests runsignaturetests )
endif()

add_custom_command( OUTPUT signatureinfocmd COMMAND echo Builds PALISADEsignature and these apps: ${PKEAPPS} )
add_custom_target( signatureinfo DEPENDS signatureinfocmd )
