include_directories(${YAF_INCLUDE_DIRS})

add_definitions(-DBUILDING_YAFRAYPLUGIN)

set(basictex_SRCS basictex.cc noise.cc getobject.c imagetex.cc)
add_library(basictex SHARED ${basictex_SRCS})
target_link_libraries(basictex yafaraycore)

add_library(basicnodes SHARED basicnodes.cc layernode.cc)
target_link_libraries(basicnodes yafaraycore)

install (TARGETS basictex basicnodes ${YAF_TARGET_TYPE} DESTINATION ${YAF_PLUGIN_DIR})
