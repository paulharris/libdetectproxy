#include <detectproxy/detectproxy.hpp>

#include <iostream>
#include <vector>
#include <string>

using namespace std;


int main(int argc, char** argv)
{
   vector<string> urls;
   urls.push_back("http://yahoo.com");
   // TODO with newer compiler urls.push_back(u"http://見.香港/");

   for (size_t i = 0; i != urls.size(); ++i)
   {
      // TODO output to wcout so windows command line can print correctly
      cout << "Checking for " << urls[i] << endl;
      detectproxy(urls[i], &cout);
   }

   return 0;
}
