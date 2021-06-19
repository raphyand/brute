
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

//Additional Utility function to easily print out
void PrintMatchResult(string match_result_type, string word, const passwd& target){
  cout << "\n" << match_result_type << endl;
  cout << "matched!\n";
  cout << target << "\n";
  std::cout << "Word: \t" << word << "\n\n"; 
}

int main(int argc, char const* argv[]) {
  if (argc < 3) {
    std::cout << "Please provide an input password file.\n";
    std::cout << "Please provide a dictionary file.";
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

    // Need to generate a whole bunch of hashes and find ones that match
    //Might want to make a separate list or vector of salts
    //Convenient to separate salts, since you have a list of targets
  ifstream  words(argv[2]);
  if(!words.is_open()){
      cout << "The dictionary wasn't opened. Uh oh.\n";
      return 1;
  }
  std::string word;
  while(getline(words, word)){

    for(auto target : targets){
      
      // Find and Test all words of the dictionary, AS they are, in the entry.
      // Also happens to be ALL LOWERCASE 
      char* hash = crypt(word.c_str(), target.salt.c_str());
      string hash_str(hash);
      if(hash_str == target.des_hash){
        PrintMatchResult("Initial test: Normal Dictionary Entries, unmodified.", word, target);
      }

      // Test capitalization of the words
      string word_capitalized = word.c_str();
      word_capitalized[0] = toupper(word_capitalized[0]);
      char* hash_capitalized = crypt(word_capitalized.c_str(), target.salt.c_str());
      string hash_str_capitalized(hash_capitalized);
      if(hash_str_capitalized == target.des_hash){
        PrintMatchResult("Capitalized Word test:", word_capitalized, target);
      }
      
      // Test all UPPERCASE
      string all_upper_case = word.c_str();
      for(int i = 0; i < all_upper_case.size(); i++)
        all_upper_case[i] = toupper(all_upper_case[i]);

      char* hash_upper = crypt(all_upper_case.c_str(), target.salt.c_str());
      string hash_str_upper(hash_upper);
      if(hash_str_upper == target.des_hash){
        PrintMatchResult("ALL UPPER CASES:", all_upper_case, target);
      }
      //Append numbers 1 to 100 at the end of each word
      
      //Append one special character to end of word

    }

  }

  words.close();

  
  //"elephant\0"
  //base case
  // base string with \0\0\0\0\0\0\0
  //leftmost, you start it


  return 0;
}
/*26 abcdefghijklmnopqrstuvwxyz*/
/*26 ABCDEFGHIJKLMNOPQRSTUVWXYZ*/
/*10 0123456789*/
/*33 !@#$%^&*()_+-=`~Pp[|\:"";',./<>?] */
/*1 ' '*/

