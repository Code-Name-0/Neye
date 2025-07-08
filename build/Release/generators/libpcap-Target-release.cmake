# Avoid multiple calls to find_package to append duplicated properties to the targets
include_guard()########### VARIABLES #######################################################################
#############################################################################################
set(libpcap_FRAMEWORKS_FOUND_RELEASE "") # Will be filled later
conan_find_apple_frameworks(libpcap_FRAMEWORKS_FOUND_RELEASE "${libpcap_FRAMEWORKS_RELEASE}" "${libpcap_FRAMEWORK_DIRS_RELEASE}")

set(libpcap_LIBRARIES_TARGETS "") # Will be filled later


######## Create an interface target to contain all the dependencies (frameworks, system and conan deps)
if(NOT TARGET libpcap_DEPS_TARGET)
    add_library(libpcap_DEPS_TARGET INTERFACE IMPORTED)
endif()

set_property(TARGET libpcap_DEPS_TARGET
             APPEND PROPERTY INTERFACE_LINK_LIBRARIES
             $<$<CONFIG:Release>:${libpcap_FRAMEWORKS_FOUND_RELEASE}>
             $<$<CONFIG:Release>:${libpcap_SYSTEM_LIBS_RELEASE}>
             $<$<CONFIG:Release>:>)

####### Find the libraries declared in cpp_info.libs, create an IMPORTED target for each one and link the
####### libpcap_DEPS_TARGET to all of them
conan_package_library_targets("${libpcap_LIBS_RELEASE}"    # libraries
                              "${libpcap_LIB_DIRS_RELEASE}" # package_libdir
                              "${libpcap_BIN_DIRS_RELEASE}" # package_bindir
                              "${libpcap_LIBRARY_TYPE_RELEASE}"
                              "${libpcap_IS_HOST_WINDOWS_RELEASE}"
                              libpcap_DEPS_TARGET
                              libpcap_LIBRARIES_TARGETS  # out_libraries_targets
                              "_RELEASE"
                              "libpcap"    # package_name
                              "${libpcap_NO_SONAME_MODE_RELEASE}")  # soname

# FIXME: What is the result of this for multi-config? All configs adding themselves to path?
set(CMAKE_MODULE_PATH ${libpcap_BUILD_DIRS_RELEASE} ${CMAKE_MODULE_PATH})

########## GLOBAL TARGET PROPERTIES Release ########################################
    set_property(TARGET libpcap::libpcap
                 APPEND PROPERTY INTERFACE_LINK_LIBRARIES
                 $<$<CONFIG:Release>:${libpcap_OBJECTS_RELEASE}>
                 $<$<CONFIG:Release>:${libpcap_LIBRARIES_TARGETS}>
                 )

    if("${libpcap_LIBS_RELEASE}" STREQUAL "")
        # If the package is not declaring any "cpp_info.libs" the package deps, system libs,
        # frameworks etc are not linked to the imported targets and we need to do it to the
        # global target
        set_property(TARGET libpcap::libpcap
                     APPEND PROPERTY INTERFACE_LINK_LIBRARIES
                     libpcap_DEPS_TARGET)
    endif()

    set_property(TARGET libpcap::libpcap
                 APPEND PROPERTY INTERFACE_LINK_OPTIONS
                 $<$<CONFIG:Release>:${libpcap_LINKER_FLAGS_RELEASE}>)
    set_property(TARGET libpcap::libpcap
                 APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
                 $<$<CONFIG:Release>:${libpcap_INCLUDE_DIRS_RELEASE}>)
    # Necessary to find LINK shared libraries in Linux
    set_property(TARGET libpcap::libpcap
                 APPEND PROPERTY INTERFACE_LINK_DIRECTORIES
                 $<$<CONFIG:Release>:${libpcap_LIB_DIRS_RELEASE}>)
    set_property(TARGET libpcap::libpcap
                 APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS
                 $<$<CONFIG:Release>:${libpcap_COMPILE_DEFINITIONS_RELEASE}>)
    set_property(TARGET libpcap::libpcap
                 APPEND PROPERTY INTERFACE_COMPILE_OPTIONS
                 $<$<CONFIG:Release>:${libpcap_COMPILE_OPTIONS_RELEASE}>)

########## For the modules (FindXXX)
set(libpcap_LIBRARIES_RELEASE libpcap::libpcap)
