
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <regex>
#include <streambuf>
#include <string>
#include <utility>

#if defined(__linux__)
#include <crypt.h>
#elif defined(__FreeBSD__)
#include <unistd.h>
#elif defined(__APPLE__) && defined(__MACH__)
#include <unistd.h>
#else
#pragma message("Missing header for crypt().")
#endif

#if defined(_WIN32) || defined(_WIN64)
#pragma message("Windoze is not supported.")
#endif

using namespace std;

struct passwd {
  std::string login;
  std::string salt;
  std::string des_hash;
  std::string name;
};

passwd MakePasswd(const std::string& login, const std::string& hash,
                  const std::string& name) {
  passwd p;
  p.login = login;
  p.salt = hash.substr(0, 2);
  p.des_hash = hash;
  p.name = name;
  return p;
}

void PrintPasswd(const passwd& p) {
  cout << p.login << ":" << p.salt << p.des_hash << ":" << p.name << "\n";
}

std::ostream& operator<<(std::ostream& out, const passwd& p) {
  out << p.login << ":" << p.salt << p.des_hash << ":" << p.name;
  return out;
}

int main(int argc, char const* argv[]) {
  if (argc < 2) {
    std::cout << "Please provide an input password file.\n";
    std::cout << "Exiting.\n";
    return 1;
  }
  // Open the file provided as an argument.
  ifstream in(argv[1]);
  if (!in.is_open()) {
    cout << "Input file " << argv[1] << " could not be opened.\n";
    return 1;
  }
  // Declare s, measure how many bytes are in the fstream `in` and
  // rewind to the beginning of the file.
  string s;
  in.seekg(0, ios::end);
  s.reserve(in.tellg());
  in.seekg(0, ios::beg);
  // Copy the contents of `in` to `s`
  s.assign((std::istreambuf_iterator<char>(in)),
           std::istreambuf_iterator<char>());
  // Close `in`
  in.close();

  // A regular expression for passing Unix password files.
  std::regex passswd_regex(
      "([A-z]+):([A-z0-9\\.\\/"
      "]+):\\d+:\\d+:\\w+:\\d+:\\d+:(\\w+\\s+\\w+\\s?\\w*):[A-z\\/]+:[A-z\\/]+",
      std::regex_constants::ECMAScript);

  auto passwd_begin = std::sregex_iterator(s.begin(), s.end(), passswd_regex);
  auto passwd_end = std::sregex_iterator();
  std::smatch passwd_match;
  std::vector<passwd> targets;
  // Search through `s` looking for matches with `passwd_regex`.
  while (regex_search(s, passwd_match, passswd_regex)) {
    cout << "searched and matched: " << passwd_match.str() << "\n";
    for (size_t i = 0; i < passwd_match.size(); i++) {
      cout << "\t" << i << ": " << passwd_match[i] << "\n";
    }
    // Create a passwd struct
    auto p = MakePasswd(passwd_match[1], passwd_match[2], passwd_match[3]);
    // Copy the passwd struct into a vector named `targets`
    targets.push_back(p);
    s = passwd_match.suffix();
  }

  // Here's a good spot to start brute forcing the passwords...

  return 0;
}
