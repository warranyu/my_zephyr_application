#-------------------------------------------------------------------------------
# Zephyr Example Application
#
# Copyright (c) 2021 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0

#cmake_minimum_required(VERSION 3.13.1)
#find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

#project(app LANGUAGES C VERSION 1.0.0)

#configure_file(app_version.h.in ${CMAKE_BINARY_DIR}/app/include/app_version.h)
#target_include_directories(app PRIVATE ${CMAKE_BINARY_DIR}/app/include src)

#target_sources(app PRIVATE src/main.c)


# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(app LANGUAGES C VERSION 1.0.0)

if(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED AND
    (CONFIG_NET_SAMPLE_PSK_HEADER_FILE STREQUAL "dummy_psk.h"))
  add_custom_target(development_psk
    COMMAND ${CMAKE_COMMAND} -E echo "----------------------------------------------------------"
    COMMAND ${CMAKE_COMMAND} -E echo "--- WARNING: Using dummy PSK! Only suitable for        ---"
    COMMAND ${CMAKE_COMMAND} -E echo "--- development. Set NET_SAMPLE_PSK_HEADER_FILE to use ---"
    COMMAND ${CMAKE_COMMAND} -E echo "--- own pre-shared key.                                ---"
    COMMAND ${CMAKE_COMMAND} -E echo "----------------------------------------------------------"
  )
  add_dependencies(app development_psk)
endif()

target_sources(                     app PRIVATE src/echo-server.c)
target_sources_ifdef(CONFIG_NET_UDP app PRIVATE src/udp.c)
target_sources_ifdef(CONFIG_NET_TCP app PRIVATE src/tcp.c)
target_sources_ifdef(CONFIG_NET_VLAN app PRIVATE src/vlan.c)
target_sources_ifdef(CONFIG_NET_L2_IPIP app PRIVATE src/tunnel.c)

include(${ZEPHYR_BASE}/samples/net/common/common.cmake)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

foreach(inc_file
    ca.der
    server.der
    server_privkey.der
    echo-apps-cert.der
    echo-apps-key.der
    )
  generate_inc_file_for_target(
    app
    src/${inc_file}
    ${gen_dir}/${inc_file}.inc
    )
endforeach()

