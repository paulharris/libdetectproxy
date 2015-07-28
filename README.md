# libdetectproxy
Detect network proxy - currectly for Windows only

Its designed for detecting the proxy once in a while,
it doesn't cache internet sessions etc, so it could be
relatively slow if you are querying it a lot.

I will be using these with NTLM proxies most of the time.

Compiles for C++, so I can use std::string objects,
but could be converted to C.

HOW TO USE:
```c++
string proxy = detect_proxy_for_url(target_url);
```
Now you can feed the "proxy" into libCurl,
it will be something like proxy.host.com:8888

Note that to get libCurl to authenticate against NTLM
proxies, you must also set user/pass to blank strings "".

Note that detect_proxy_for_url() will THROW a runtime_error if
there is some sort of error.

You can also do:
```c++
string proxy = detect_proxy_for_url(target_url, &std::cout);
```
to see messages during the detection process.

REQUIRES:
 * Boost-Nowide, I use my fork on github at
   https://github.com/paulharris/boost-nowide
   This is for converting wide strings to UTF-8,
   because wstring drives me insane.

TODO:
 * CMake build
 * Improve the proxy list splitting (its very naive at the moment)
 * Handle the proxy-bypass list
 * Cache the internal internet session - threadsafe?
 * Test situation where proxy server does not need or want user/pass.
 * Handle WinHttpGetProxyForUrl potential crashes
   (I have seen mention that old McAfee can cause crashes).

