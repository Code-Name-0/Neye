########## MACROS ###########################################################################
#############################################################################################

# Requires CMake > 3.15
if(${CMAKE_VERSION} VERSION_LESS "3.15")
    message(FATAL_ERROR "The 'CMakeDeps' generator only works with CMake >= 3.15")
endif()

if(libpcap_FIND_QUIETLY)
    set(libpcap_MESSAGE_MODE VERBOSE)
else()
    set(libpcap_MESSAGE_MODE STATUS)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/cmakedeps_macros.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/libpcapTargets.cmake)
include(CMakeFindDependencyMacro)

check_build_type_defined()

foreach(_DEPENDENCY ${libpcap_FIND_DEPENDENCY_NAMES} )
    # Check that we have not already called a find_package with the transitive dependency
    if(NOT ${_DEPENDENCY}_FOUND)
        find_dependency(${_DEPENDENCY} REQUIRED ${${_DEPENDENCY}_FIND_MODE})
    endif()
endforeach()

set(libpcap_VERSION_STRING "1.10.4")
set(libpcap_INCLUDE_DIRS ${libpcap_INCLUDE_DIRS_RELEASE} )
set(libpcap_INCLUDE_DIR ${libpcap_INCLUDE_DIRS_RELEASE} )
set(libpcap_LIBRARIES ${libpcap_LIBRARIES_RELEASE} )
set(libpcap_DEFINITIONS ${libpcap_DEFINITIONS_RELEASE} )


# Only the last installed configuration BUILD_MODULES are included to avoid the collision
foreach(_BUILD_MODULE ${libpcap_BUILD_MODULES_PATHS_RELEASE} )
    message(${libpcap_MESSAGE_MODE} "Conan: Including build module from '${_BUILD_MODULE}'")
    include(${_BUILD_MODULE})
endforeach()


