cmake_minimum_required(VERSION 3.26)
project(shadowjmp C ASM)

set(CMAKE_C_STANDARD 11)

# Add C sources
add_executable(shadowjmp main.c instrumentation.c syscalls.c keylogger.c)

# ASM sources
set(ASM_SOURCES syscalls.asm instrumentation.asm)
foreach(ASM_SRC IN LISTS ASM_SOURCES)
    get_filename_component(ASM_OBJ ${ASM_SRC} NAME_WE)
    set(ASM_OBJ_FILE ${CMAKE_CURRENT_BINARY_DIR}/${ASM_OBJ}.obj)
    add_custom_command(OUTPUT ${ASM_OBJ_FILE}
            COMMAND ml64.exe /c /nologo /Zi /Fo${ASM_OBJ_FILE} /Fl"" /W3 /errorReport:prompt /Ta ${CMAKE_CURRENT_SOURCE_DIR}/${ASM_SRC}
            DEPENDS ${ASM_SRC})
    list(APPEND ASM_OBJECTS ${ASM_OBJ_FILE})
endforeach()

# Add ASM objects to the target
target_sources(shadowjmp PRIVATE ${ASM_OBJECTS})

# Link Libraries
target_link_libraries(shadowjmp dbghelp)
