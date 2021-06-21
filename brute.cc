// Raphael S. Andaya
// CPSC 353-01
// 2021-06-13
// raphyand@csu.fullerton.edu
// @raphyand
//
// Assignment 01
//
// Various trials to match passwords in master password file.
//

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

// Additional Utility function to easily print out
void PrintMatchResult(string match_result_type, string word,
                      const passwd& target) {
  cout << "\n" << match_result_type << endl;
  cout << "matched!\n";
  cout << target << "\n";
  cout << "Word: \t" << word << endl << endl;
}

// How to use: ./brute <password file> <path to dictionary words>
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
  // Might want to make a separate list or vector of salts
  // Convenient to separate salts, since you have a list of targets
  ifstream words(argv[2]);
  if (!words.is_open()) {
    cout << "The dictionary wasn't opened. Uh oh.\n";
    return 1;
  }
  std::string word;
  while (getline(words, word)) {
    for (auto target : targets) {
      // Find and Test all words of the dictionary, AS they are, in the entry.
      // (Lowercase)
      char* hash = crypt(word.c_str(), target.salt.c_str());
      string hash_str(hash);
      if (hash_str == target.des_hash) {
        PrintMatchResult("Initial test: Normal Dictionary Entries, unmodified.",
                         word, target);
      }

      // Test capitalization of the words
      string word_capitalized = word;
      word_capitalized[0] = toupper(word_capitalized[0]);
      char* hash_capitalized =
          crypt(word_capitalized.c_str(), target.salt.c_str());
      string hash_str_capitalized(hash_capitalized);
      if (hash_str_capitalized == target.des_hash) {
        PrintMatchResult("Capitalized Word test:", word_capitalized, target);
      }
      // Test all UPPERCASE
      string all_upper_case = word;
      for (int i = 0; i < all_upper_case.length(); i++) {
        all_upper_case[i] = toupper(all_upper_case[i]);
      }
      char* hash_upper = crypt(all_upper_case.c_str(), target.salt.c_str());
      string hash_str_upper(hash_upper);
      if (hash_str_upper == target.des_hash) {
        PrintMatchResult("ALL UPPER CASES:", all_upper_case, target);
      }

      // Append numbers 1 to 100 at the end of each word
      string suffix_number_word = word;
      for (int suffix = 0; suffix < 100; suffix++) {
        suffix_number_word.append(to_string(suffix));
        char* hash_num_suffix =
            crypt(suffix_number_word.c_str(), target.salt.c_str());
        string hash_str_num_suffix(hash_num_suffix);
        if (hash_str_num_suffix == target.des_hash) {
          PrintMatchResult("Number Suffixed:", suffix_number_word, target);
        }
        // Remove appended characters to try next number
        for (int i = 0; i < to_string(suffix).length(); i++) {
          suffix_number_word.pop_back();
        }
      }

      // Append numbers 1 to 100 at the beginning of each word
      string prefix_number_word = word;
      for (int prefix = 0; prefix < 101; prefix++) {
        prefix_number_word = to_string(prefix).append(prefix_number_word);
        char* hash_num_prefix =
            crypt(prefix_number_word.c_str(), target.salt.c_str());
        string hash_str_num_prefix(hash_num_prefix);
        if (hash_str_num_prefix == target.des_hash) {
          PrintMatchResult("Number Suffixed:", prefix_number_word, target);
        }
        // Remove appended characters to try next number
        for (int i = 0; i < to_string(prefix).length(); i++) {
          prefix_number_word.erase(0, 1);
        }
      }

      // Replace every o with a 0
      string word_replace_o = word;
      bool has_o = false;
      for (int i = 0; i < word_replace_o.length(); i++) {
        if (word_replace_o[i] == 'o') {
          word_replace_o.replace(i, 1, "0");
          has_o = true;
        }
      }
      char* hash_rep_o = crypt(word_replace_o.c_str(), target.salt.c_str());
      string hash_str_rep_o(hash_rep_o);
      if (hash_str_rep_o == target.des_hash && has_o) {
        PrintMatchResult("Words with o replaced with 0", word_replace_o,
                         target);
      }
      has_o = false;
      // Replace every i with a 1
      string word_replace_i = word;
      bool has_i = false;
      for (int i = 0; i < word_replace_i.length(); i++) {
        if (word_replace_i[i] == 'i') {
          word_replace_i.replace(i, 1, "1");
          has_i = true;
        }
      }
      char* hash_rep_i = crypt(word_replace_i.c_str(), target.salt.c_str());
      string hash_str_rep_i(hash_rep_i);
      if (hash_str_rep_i == target.des_hash && has_i) {
        PrintMatchResult("Words with i replaced with 1", word_replace_i,
                         target);
      }
      has_i = false;

      // Append one special character to end of word ascii values 32 - 47
      string word_ascii = word;
      for (char i = ' '; i < '0'; i++) {
        string ascii(1, i);
        word_ascii.append(ascii);
        char* hash_ascii = crypt(word_ascii.c_str(), target.salt.c_str());
        string hash_str_ascii(hash_ascii);
        if (hash_str_ascii == target.des_hash) {
          PrintMatchResult("Ascii Special Characters appended.", word_ascii,
                           target);
        }
        for (int i = 0; i < ascii.length(); i++) {
          word_ascii.pop_back();
        }
      }

      // End
    }  // End of While
  }
  words.close();
  // "elephant\0"
  // base case
  // base string with \0\0\0\0\0\0\0
  // leftmost, you start it
  return 0;
}
/*26 abcdefghijklmnopqrstuvwxyz*/
/*26 ABCDEFGHIJKLMNOPQRSTUVWXYZ*/
/*10 0123456789*/
/*33 !@#$%^&*()_+-=`~Pp[|\:"";',./<>?] */
/*1 ' '*/