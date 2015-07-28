// for detecting proxies
#ifndef __WINDOWS__

std::string detect_proxy_for_url(std::string const& url, std::ostream * log)
{
   // TODO: implement for non-Windows
   return std::string();
}

#else
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#include "detect_proxy.hpp"

#include <stdexcept>
#include <string>
#include <boost/nowide/convert.hpp>


namespace nowide = boost::nowide;
using std::ostream;
using std::string;
using std::wstring;
using std::runtime_error;

#define VERBOSE_LOG(x) { if (log) *log << x << std::endl; }



static void throw_GetLastError( string context )
{
   DWORD error = GetLastError();

   // output log message that we failed to get proxy
   LPSTR err_ptr = NULL;

   FormatMessageA(
         FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
         NULL,
         error,
         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
         (LPSTR)&err_ptr,  // yes, this is the offical pointer hack
         0,
         NULL
         );

   if (err_ptr)
   {
      string errtxt(err_ptr);
      LocalFree(err_ptr);
      throw runtime_error("Error from " + context + " " + errtxt);
   }
}



class WinHttpProxyInfo
{
public:
   WINHTTP_PROXY_INFO info;

   WinHttpProxyInfo()
   {
      memset(&info, 0, sizeof(info));
   }

   ~WinHttpProxyInfo()
   {
      if (info.lpszProxy) GlobalFree(info.lpszProxy);
      if (info.lpszProxyBypass) GlobalFree(info.lpszProxyBypass);
   }
};

class WinHInternet
{
public:
   HINTERNET handle;

   WinHInternet() : handle(NULL)
   {
      handle = WinHttpOpen(
         NULL,
         WINHTTP_ACCESS_TYPE_NO_PROXY,
         WINHTTP_NO_PROXY_NAME,
         WINHTTP_NO_PROXY_BYPASS,
         // NOTE: no WINHTTP_FLAG_ASYNC
         0
         );

      if (!handle)
         throw_GetLastError("WinHttpOpen");

      // For WinHTTP's out-of-process PAC resolution.
      BOOL rv = WinHttpSetTimeouts(handle, 10000, 10000, 5000, 5000);
      if (!rv)
         throw_GetLastError("WinHttpSetTimeouts");
   }

   ~WinHInternet()
   {
      if (handle)
         WinHttpCloseHandle(handle);
   }
};


struct ProxyConfig
{
   string proxy_list;
   string bypass_list;
};

struct IEProxyConfig
{
   string autoconfig_url;
   bool autodetect_enabled;
   ProxyConfig cfg;
};


static IEProxyConfig read_IE_proxy_config()
{
   WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config;
   memset(&config, 0, sizeof(config));
   if (not WinHttpGetIEProxyConfigForCurrentUser(&config))
      throw_GetLastError( "WinHttpGetIEProxyConfigForCurrentUser" );

   IEProxyConfig cfg;
   cfg.autodetect_enabled = (config.fAutoDetect == TRUE);

   if (config.lpszAutoConfigUrl)
   {
      cfg.autoconfig_url = nowide::narrow(config.lpszAutoConfigUrl);
      GlobalFree(config.lpszAutoConfigUrl);
   }

   if (config.lpszProxy)
   {
      cfg.cfg.proxy_list = nowide::narrow(config.lpszProxy);
      GlobalFree(config.lpszProxy);
   }

   if (config.lpszProxyBypass)
   {
      cfg.cfg.bypass_list = nowide::narrow(config.lpszProxyBypass);
      GlobalFree(config.lpszProxyBypass);
   }

   return cfg;
}



static bool detect_proxy( WinHInternet & session, WINHTTP_AUTOPROXY_OPTIONS options, string const& target_url, ProxyConfig * out_config, ostream * log )
{
   options.fAutoLogonIfChallenged = FALSE;

   // Basically, need to first resolve without autologon,
   // and then try again if we fail, this time with autologon.
   //
   // Get better performance from WinHTTP's out-of-process resolver,
   // which can return the cached result for the whole computer,
   // if its asked for the answer without autologon first.

   WinHttpProxyInfo info;
   BOOL ok = WinHttpGetProxyForUrl(
         session.handle,
         nowide::widen(target_url).c_str(),
         &options,
         &info.info
         );

   if (not ok)
   {
      if (ERROR_WINHTTP_LOGIN_FAILURE == GetLastError())
      {
         options.fAutoLogonIfChallenged = TRUE;
         ok = WinHttpGetProxyForUrl(
               session.handle,
               nowide::widen(target_url).c_str(),
               &options,
               &info.info
               );
      }

      // still not ok, then throw an error
      if (not ok)
         throw_GetLastError("WinHttpGetProxyForUrl");
   }

   // successful ? at least, no errors...

   switch (info.info.dwAccessType)
   {
      case WINHTTP_ACCESS_TYPE_NO_PROXY:
         VERBOSE_LOG("Detected no-proxy, using DIRECT");
         return true;

      case WINHTTP_ACCESS_TYPE_NAMED_PROXY:
         {
            VERBOSE_LOG("Detected named-proxy");
            // The list is something like
            // ([<scheme>=][<scheme>"://"]<server>[":"<port>])
            //
            // with ; semicolon separators, and probably no "DIRECT"
            // 
            // lets just take the first one off the list...
            // and curl can handle scheme://host:port so we can pass that directly
            //
            // Will assume there is no <scheme>=
            // and no SOCKS5 or other non-http proxies.

            // Note: no need to free these strings, 'info' will do that for us.

            if (info.info.lpszProxy)
               out_config->proxy_list = nowide::narrow(info.info.lpszProxy);

            if (info.info.lpszProxyBypass)
               out_config->bypass_list = nowide::narrow(info.info.lpszProxyBypass);

            return true;
         }

      default:
         VERBOSE_LOG("Could not detect proxy");
         return false;
   }
}




string proxy_for_url( string const& target_url, ostream * log )
{
   // stage 1: get user config

   // load IE defaults
   IEProxyConfig ie_proxy_config = read_IE_proxy_config();

   // init with IE's settings
   ProxyConfig proxy_config = ie_proxy_config.cfg;

   VERBOSE_LOG("IE proxy list: " + proxy_config.proxy_list);
   VERBOSE_LOG("IE bypass list: " + proxy_config.bypass_list);

   if (ie_proxy_config.autodetect_enabled or not ie_proxy_config.autoconfig_url.empty())
   {
      // TODO: IF no errors, you can keep this session intact for the next function call,
      // but be aware of threading issues, and note that the session has to be closed
      // if there was a timeout or error (apparently).
      WinHInternet session;

      bool got_auto = false;
      ProxyConfig autocfg;

      if (not ie_proxy_config.autoconfig_url.empty())
      {
         VERBOSE_LOG("Trying PAC detection");
         //////// First: PAC autodetect /////////

         WINHTTP_AUTOPROXY_OPTIONS options = {0};

         wstring pac_url = nowide::widen(ie_proxy_config.autoconfig_url);
         options.lpszAutoConfigUrl = pac_url.c_str();
         options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;

         got_auto = detect_proxy(session, options, target_url, &autocfg, log);
      }

      if (ie_proxy_config.autodetect_enabled)
         VERBOSE_LOG("Could try DNS/DHCP detection");

      // Do the DHCP / DNS-A detection as well, like WebRTC.
      // I don't know why Chromium doesn't do this step... it mentions there is
      // some problem but doesn't mention what the problem is.
      if (not got_auto and ie_proxy_config.autodetect_enabled)
      {
         VERBOSE_LOG("Trying DNS/DHCP detection");
         WINHTTP_AUTOPROXY_OPTIONS options = {0};
         options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
         options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;

         got_auto = detect_proxy(session, options, target_url, &autocfg, log);
      }

      // if detected, then we use this configuration instead of IE's custom settings
      if (got_auto)
      {
         VERBOSE_LOG("Detected successfully");
         proxy_config = autocfg;
      }
   }


   VERBOSE_LOG("Final proxy list: " + proxy_config.proxy_list);
   VERBOSE_LOG("Final bypass list: " + proxy_config.bypass_list);

   // just get the first item... TODO this is very naive.
   return proxy_config.proxy_list.substr(0, proxy_config.proxy_list.find(';'));
}
#endif
