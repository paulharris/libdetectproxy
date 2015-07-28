#pragma once

#include <string>
#include <ostream>

// log: optional printouts
std::string detect_proxy_for_url(std::string const& url, std::ostream * log = NULL);
