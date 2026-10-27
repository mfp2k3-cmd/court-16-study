# Locate the host OpenSSL before shadPS4's externals configure its LibreSSL
# fallback. This avoids the current MinGW/Clang incompatibility in LibreSSL's
# endian feature macros while retaining HTTPS support in the runtime.
if(WIN32)
    foreach(_nba16_openssl_root IN ITEMS
            "$ENV{MINGW_PREFIX}"
            "$ENV{MSYSTEM_PREFIX}"
            "C:/msys64/clang64"
            "C:/msys64/ucrt64")
        if(_nba16_openssl_root AND
           EXISTS "${_nba16_openssl_root}/include/openssl/ssl.h")
            set(OPENSSL_ROOT_DIR "${_nba16_openssl_root}" CACHE PATH "" FORCE)
            break()
        endif()
    endforeach()
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

find_package(OpenSSL QUIET)
