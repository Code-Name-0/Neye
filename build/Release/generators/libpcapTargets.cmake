# Load the debug and release variables
file(GLOB DATA_FILES "${CMAKE_CURRENT_LIST_DIR}/libpcap-*-data.cmake")

foreach(f ${DATA_FILES})
    include(${f})
endforeach()

# Create the targets for all the components
foreach(_COMPONENT ${libpcap_COMPONENT_NAMES} )
    if(NOT TARGET ${_COMPONENT})
        add_library(${_COMPONENT} INTERFACE IMPORTED)
        message(${libpcap_MESSAGE_MODE} "Conan: Component target declared '${_COMPONENT}'")
    endif()
endforeach()

if(NOT TARGET libpcap::libpcap)
    add_library(libpcap::libpcap INTERFACE IMPORTED)
    message(${libpcap_MESSAGE_MODE} "Conan: Target declared 'libpcap::libpcap'")
endif()
# Load the debug and release library finders
file(GLOB CONFIG_FILES "${CMAKE_CURRENT_LIST_DIR}/libpcap-Target-*.cmake")

foreach(f ${CONFIG_FILES})
    include(${f})
endforeach()