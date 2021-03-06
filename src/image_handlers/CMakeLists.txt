include_directories(${YAF_INCLUDE_DIRS} ${ZLIB_INCLUDE_DIR})

if(WITH_OpenEXR)
	include_directories(${OPENEXR_INCLUDE_DIRS})
endif(WITH_OpenEXR)

if(WITH_JPEG)
	include_directories(${JPEG_INCLUDE_DIR})
endif(WITH_JPEG)

if(WITH_PNG)
	include_directories(${PNG_INCLUDE_DIR})
endif(WITH_PNG)

if(WITH_TIFF)
	include_directories(${TIFF_INCLUDE_DIR})
endif(WITH_TIFF)

add_definitions(-DBUILDING_YAFRAYPLUGIN)

if(WITH_OpenEXR)
add_library(exrHandler SHARED exrHandler.cc)
target_link_libraries(exrHandler yafaraycore ${OPENEXR_LIBRARIES})
endif(WITH_OpenEXR)

if(WITH_JPEG)
add_library(jpgHandler SHARED jpgHandler.cc)
target_link_libraries(jpgHandler yafaraycore ${JPEG_LIBRARY})
endif(WITH_JPEG)

if(WITH_PNG)
add_library(pngHandler SHARED pngHandler.cc)
target_link_libraries(pngHandler yafaraycore ${PNG_LIBRARIES})
endif(WITH_PNG)

if(WITH_TIFF)
add_library(tifHandler SHARED tifHandler.cc)
target_link_libraries(tifHandler yafaraycore ${TIFF_LIBRARY})
endif(WITH_TIFF)

add_library(tgaHandler SHARED tgaHandler.cc)
target_link_libraries(tgaHandler yafaraycore)

add_library(hdrHandler SHARED hdrHandler.cc)
target_link_libraries(hdrHandler yafaraycore)

if(WITH_OpenEXR)
	install (TARGETS exrHandler ${YAF_TARGET_TYPE} DESTINATION ${YAF_PLUGIN_DIR})
endif(WITH_OpenEXR)

if(WITH_JPEG)
	install (TARGETS jpgHandler ${YAF_TARGET_TYPE} DESTINATION ${YAF_PLUGIN_DIR})
endif(WITH_JPEG)

if(WITH_PNG)
	install (TARGETS pngHandler ${YAF_TARGET_TYPE} DESTINATION ${YAF_PLUGIN_DIR})
endif(WITH_PNG)

if(WITH_TIFF)
	install (TARGETS tifHandler ${YAF_TARGET_TYPE} DESTINATION ${YAF_PLUGIN_DIR})
endif(WITH_TIFF)

install (TARGETS tgaHandler hdrHandler ${YAF_TARGET_TYPE} DESTINATION ${YAF_PLUGIN_DIR})

