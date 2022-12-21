include(FindPackageHandleStandardArgs)

find_path(mcl_INCLUDE_DIRS NAMES mcl/bn256.hpp)
find_library(mcl_LIBRARIES NAMES mcl)
find_library(mclbn256_LIBRARIES NAMES mclbn256)

find_package_handle_standard_args(mcl DEFAULT_MSG mcl_LIBRARIES mclbn256_LIBRARIES mcl_INCLUDE_DIRS)

mark_as_advanced(
        mcl_LIBRARIES
        mclbn256_LIBRARIES
        mcl_INCLUDE_DIRS)