cmake_minimum_required(VERSION 3.20)
set(PSXRECOMP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/psxrecomp" CACHE PATH
    "Path to the pinned PSXRecomp framework")
if(NOT EXISTS "${PSXRECOMP_ROOT}/runtime/runtime.cmake")
    message(FATAL_ERROR
        "PSXRecomp runtime is missing: ${PSXRECOMP_ROOT}/runtime/runtime.cmake\n"
        "This project expects the psxrecomp framework checkout at ${PSXRECOMP_ROOT}.\n"
        "Run: git submodule update --init --recursive\n"
        "If psxrecomp/ is not a submodule, set -DPSXRECOMP_ROOT=<path-to-psxrecomp>.")
endif()

project(SyphonFilter2Recompiled LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

# Game code and the BIOS backend are generated on the player's machine (setup
# wizard or RetComM) from their own disc and a legal SCPH-1001 BIOS dump;
# neither exists in Git or CI.
# Real-BIOS title: only the SCPH-1001 backend is built. This must match the
# package wrapper's --omit-openbios, or the runtime asks for a bundled OpenBIOS
# image the package does not ship.
set(PSXRECOMP_BIOS_STEMS "SCPH1001" CACHE STRING "" FORCE)
set(PSX_SETUP_WIZARD ON CACHE BOOL
    "Advertise first-run setup wizard + Generate & rebuild in recomp-ui" FORCE)
include("${PSXRECOMP_ROOT}/runtime/runtime.cmake")

psxrecomp_add_game_runtime(psx-runtime
    ENABLE_SETUP_WIZARD
    WINDOW_TITLE "Syphon Filter 2 Recompiled"
    EXE_NAME "Syphon_Filter_2_Recompiled"
    DEFAULT_GAME_CONFIG_PATH "game.toml"
    MAX_PLAYERS 2
    GEN_MARKER "generated/SCUS_944.51_dispatch.c"
    GEN_FULL_GLOB "generated/SCUS_944.51_full_*.c"
    CODEGEN_SETUP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/codegen_setup.c"
    # SF2's trusted mod activation plugins (Mouse Look, Widescreen, PGXP).
    EXTRAS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/sf2_mods.c"
)

# Stage runtime configs and the built-in mod catalog next to the exe for direct
# build/ launches. Only copy files that exist.
foreach(_PSX_RUNTIME_CONFIG game.toml game_options.toml)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_PSX_RUNTIME_CONFIG}")
        add_custom_command(TARGET psx-runtime POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/${_PSX_RUNTIME_CONFIG}"
                "$<TARGET_FILE_DIR:psx-runtime>/${_PSX_RUNTIME_CONFIG}"
            COMMENT "Staging ${_PSX_RUNTIME_CONFIG}"
            VERBATIM)
    endif()
endforeach()
add_custom_command(TARGET psx-runtime POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/mods"
        "$<TARGET_FILE_DIR:psx-runtime>/mods"
    COMMENT "Installing Syphon Filter 2 built-in mod catalog")
