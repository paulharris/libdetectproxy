#pragma once

#include <string>
#include <ostream>

#if defined(_WIN32) && defined(LIBDETECTPROXY_DYN_LINK)
// detectproxy_EXPORTS is automatically defined by CMake
#  if defined(detectproxy_EXPORTS)
#     define LIBDETECTPROXY_EXPORT __declspec(dllexport)
#  else
#     define LIBDETECTPROXY_EXPORT __declspec(dllimport)
#  endif
#else
#  define LIBDETECTPROXY_EXPORT
#endif

// url: the target url
// log: optional printouts
// returns the proxy that should be used for that target URL.
// will return an empty string if no proxy should be used.
// will throw runtime_error() if there was an error.
LIBDETECTPROXY_EXPORT std::string detectproxy(std::string const& target_url, std::ostream * log = NULL);

#undef LIBDETECTPROXY_EXPORT
