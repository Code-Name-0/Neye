########### AGGREGATED COMPONENTS AND DEPENDENCIES FOR THE MULTI CONFIG #####################
#############################################################################################

set(libpcap_COMPONENT_NAMES "")
if(DEFINED libpcap_FIND_DEPENDENCY_NAMES)
  list(APPEND libpcap_FIND_DEPENDENCY_NAMES )
  list(REMOVE_DUPLICATES libpcap_FIND_DEPENDENCY_NAMES)
else()
  set(libpcap_FIND_DEPENDENCY_NAMES )
endif()

########### VARIABLES #######################################################################
#############################################################################################
set(libpcap_PACKAGE_FOLDER_RELEASE "/home/rabah/.conan2/p/b/libpc78307b73c14c4/p")
set(libpcap_BUILD_MODULES_PATHS_RELEASE )


set(libpcap_INCLUDE_DIRS_RELEASE "${libpcap_PACKAGE_FOLDER_RELEASE}/include")
set(libpcap_RES_DIRS_RELEASE )
set(libpcap_DEFINITIONS_RELEASE )
set(libpcap_SHARED_LINK_FLAGS_RELEASE )
set(libpcap_EXE_LINK_FLAGS_RELEASE )
set(libpcap_OBJECTS_RELEASE )
set(libpcap_COMPILE_DEFINITIONS_RELEASE )
set(libpcap_COMPILE_OPTIONS_C_RELEASE )
set(libpcap_COMPILE_OPTIONS_CXX_RELEASE )
set(libpcap_LIB_DIRS_RELEASE "${libpcap_PACKAGE_FOLDER_RELEASE}/lib")
set(libpcap_BIN_DIRS_RELEASE )
set(libpcap_LIBRARY_TYPE_RELEASE STATIC)
set(libpcap_IS_HOST_WINDOWS_RELEASE 0)
set(libpcap_LIBS_RELEASE pcap)
set(libpcap_SYSTEM_LIBS_RELEASE )
set(libpcap_FRAMEWORK_DIRS_RELEASE )
set(libpcap_FRAMEWORKS_RELEASE )
set(libpcap_BUILD_DIRS_RELEASE )
set(libpcap_NO_SONAME_MODE_RELEASE FALSE)


# COMPOUND VARIABLES
set(libpcap_COMPILE_OPTIONS_RELEASE
    "$<$<COMPILE_LANGUAGE:CXX>:${libpcap_COMPILE_OPTIONS_CXX_RELEASE}>"
    "$<$<COMPILE_LANGUAGE:C>:${libpcap_COMPILE_OPTIONS_C_RELEASE}>")
set(libpcap_LINKER_FLAGS_RELEASE
    "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>:${libpcap_SHARED_LINK_FLAGS_RELEASE}>"
    "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>:${libpcap_SHARED_LINK_FLAGS_RELEASE}>"
    "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:${libpcap_EXE_LINK_FLAGS_RELEASE}>")


set(libpcap_COMPONENTS_RELEASE )