// Evidence harness: proves the monero-gui pinned submodule's real epee
// http_auth.cpp negotiates SHA-256 (RFC 7616) end-to-end.
// Scratch verification tool; not part of monero-gui.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX 1
#include <windows.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <list>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "net/http_auth.h"

// memwipe() normally comes from contrib/epee/src/memwipe.c, whose C source
// unconditionally includes <unistd.h> (not available under MSVC). Behavior
// equivalent on Windows: SecureZeroMemory is never optimized away.
extern "C" void* memwipe(void* ptr, size_t n)
{
  if (n)
    SecureZeroMemory(ptr, n);
  return ptr;
}

namespace http = epee::net_utils::http;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond)                                                                      \
  do                                                                                     \
  {                                                                                      \
    if (cond) { ++g_pass; std::printf("    [ok] %s\n", #cond); }                        \
    else { ++g_fail; std::printf("    [FAIL] %s (line %d)\n", #cond, __LINE__); }      \
  } while (0)

static void test_rng(size_t n, uint8_t* p)
{
  if (RAND_bytes(p, static_cast<int>(n)) != 1)
    std::abort();
}

static std::string to_lower(std::string s)
{
  for (char& c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

static std::string evp_hex(const EVP_MD* md, const std::vector<std::string>& parts)
{
  unsigned char digest[EVP_MAX_MD_SIZE]{};
  unsigned int digest_len = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, md, nullptr);
  for (const std::string& part : parts)
    EVP_DigestUpdate(ctx, part.data(), part.size());
  EVP_DigestFinal_ex(ctx, digest, &digest_len);
  EVP_MD_CTX_free(ctx);

  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  out.resize(digest_len * 2);
  for (unsigned int i = 0; i < digest_len; ++i)
  {
    out[2 * i] = hex[digest[i] >> 4];
    out[2 * i + 1] = hex[digest[i] & 0x0F];
  }
  return out;
}

static std::string sha256_hex(std::initializer_list<std::string> parts)
{
  return evp_hex(EVP_sha256(), std::vector<std::string>(parts));
}

static std::map<std::string, std::string> parse_auth(const std::string& field)
{
  std::map<std::string, std::string> out;
  const std::string lower = to_lower(field);
  size_t p = lower.find("digest");
  p = (p == std::string::npos ? 0 : p + 6);

  auto skip_ws = [&] {
    while (p < field.size() && std::isspace(static_cast<unsigned char>(field[p])))
      ++p;
  };
  skip_ws();
  while (p < field.size())
  {
    const size_t name0 = p;
    while (p < field.size() &&
           (std::isalnum(static_cast<unsigned char>(field[p])) || field[p] == '-'))
      ++p;
    const std::string name = to_lower(field.substr(name0, p - name0));
    skip_ws();
    if (p >= field.size() || field[p] != '=')
      break;
    ++p;
    skip_ws();

    std::string value;
    if (p < field.size() && field[p] == '"')
    {
      ++p;
      while (p < field.size() && field[p] != '"')
      {
        if (field[p] == '\\' && p + 1 < field.size())
          ++p;
        value.push_back(field[p++]);
      }
      if (p < field.size())
        ++p;
    }
    else
    {
      while (p < field.size() && field[p] != ',')
        value.push_back(field[p++]);
      while (!value.empty() &&
             std::isspace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    }
    out[name] = value;
    skip_ws();
    if (p < field.size() && field[p] == ',')
    {
      ++p;
      skip_ws();
      continue;
    }
    break;
  }
  return out;
}

static bool iequals(const std::string& a, const std::string& b)
{
  return a.size() == b.size() &&
         std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
           return std::tolower(static_cast<unsigned char>(x)) ==
                  std::tolower(static_cast<unsigned char>(y));
         });
}

static void section(const char* title)
{
  std::printf("\n=== %s ===\n", title);
}

// 1. Server side (monerod): what WWW-Authenticate challenges are advertised.
static void demo_server_challenges()
{
  section("1. SERVER (monerod -> GUI): WWW-Authenticate challenges");
  const http::login user{"foo", "bar"};
  http::http_server_auth server{user, test_rng};

  http::http_request_info request{};
  const auto response = server.get_response(request);
  CHECK(response.is_initialized());
  CHECK(response->m_response_code == 401);
  CHECK(response->m_additional_fields.size() == 4);

  const std::vector<std::string> expected{
      "SHA-256", "SHA-256-sess", "MD5", "MD5-sess"};
  std::size_t i = 0;
  for (const auto& entry : response->m_additional_fields)
  {
    std::printf("  WWW-Authenticate: %s\n", entry.second.c_str());
    const auto f = parse_auth(entry.second);
    CHECK(iequals(f.at("algorithm"), expected[i]));
    CHECK(f.at("qop") == "auth");
    CHECK(f.at("realm") == "monero-rpc");
    CHECK(f.at("stale") == "false");
    ++i;
  }
}

// 2. Client side (GUI): RFC 7616 negotiation + actual Authorization header.
static void demo_client_sha256()
{
  section("2. CLIENT (GUI -> node): chooses SHA-256, real Authorization header");
  constexpr char nonce[] = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
  constexpr char opaque[] = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS";
  constexpr char realm[] = "http-auth@example.org";
  constexpr char uri[] = "/dir/index.html";

  const http::login user{"Mufasa", "Circle of Life"};
  http::http_client_auth client{user};

  http::http_response_info response{};
  response.m_header_info.m_etc_fields.push_back(
      std::make_pair(std::string("WWW-authenticate"),
                     "Digest algorithm=MD5,nonce=\"e" + std::string(nonce) +
                         "\",opaque=\"e" + opaque + "\",realm=\"e" + realm +
                         "\",qop=\"auth\""));
  response.m_header_info.m_etc_fields.push_back(
      std::make_pair(std::string("WWW-authenticate"),
                     "Digest algorithm=SHA-256,nonce=\"" + std::string(nonce) +
                         "\",opaque=\"" + opaque + "\",realm=\"" + realm +
                         "\",qop=\"auth, auth-int\""));

  CHECK(client.handle_401(response) == http::http_client_auth::kSuccess);

  const auto field = client.get_auth_field("GET", uri);
  CHECK(field.is_initialized());
  std::printf("  Authorization: %s\n", field->second.c_str());

  const auto f = parse_auth(field->second);
  CHECK(iequals(f.at("algorithm"), "SHA-256")); // not MD5
  CHECK(f.at("qop") == "auth");                  // auth-int offered but unsupported
  CHECK(f.at("nc") == "00000001");
  CHECK(f.at("response").size() == 64);          // SHA-256 hex = 64 chars

  const std::string ha1 = sha256_hex({"Mufasa", ":", realm, ":", "Circle of Life"});
  const std::string ha2 = sha256_hex({"GET", ":", uri});
  const std::string expected = sha256_hex(
      {ha1, ":", nonce, ":", "00000001", ":", f.at("cnonce"), ":", "auth", ":", ha2});
  CHECK(iequals(f.at("response"), expected));

  // Official RFC 7616 section 3.9.1 vector (fixed cnonce).
  constexpr char cnonce[] = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
  const std::string rfc = sha256_hex(
      {ha1, ":", nonce, ":", "00000001", ":", cnonce, ":", "auth", ":", ha2});
  std::printf("  RFC 7616 3.9.1 vector: %s\n", rfc.c_str());
  CHECK(rfc == "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1");
}

// 3. Full dogfood + replay rejection.
static void demo_dogfood_replay()
{
  section("3. END-TO-END: SHA-256 accepted, replay rejected (stale=true)");
  const http::login user{"foo", "bar"};
  http::http_server_auth server{user, test_rng};
  http::http_client_auth client{user};

  http::http_request_info request{};
  request.m_http_method_str = "GET";
  request.m_URI = "/FOO";

  auto challenge = server.get_response(request);
  challenge->m_header_info.m_etc_fields = challenge->m_additional_fields;
  CHECK(client.handle_401(*challenge) == http::http_client_auth::kSuccess);

  const auto auth_field = client.get_auth_field(request.m_http_method_str, request.m_URI);
  std::printf("  Authorization: %s\n", auth_field->second.c_str());
  request.m_header_info.m_etc_fields.push_back(*auth_field);

  std::printf("  -> first request: ");
  const auto ok = server.get_response(request);
  if (!ok.is_initialized()) { std::printf("AUTHENTICATED (no 401)\n"); ++g_pass; }
  else { std::printf("REJECTED\n"); ++g_fail; }

  auto replay = server.get_response(request);
  CHECK(replay.is_initialized());
  const auto f = parse_auth(replay->m_additional_fields.front().second);
  std::printf("  replay response : stale=%s (new nonce issued)\n", f.at("stale").c_str());
  CHECK(f.at("stale") == "true");
}

// 4. Backwards compatibility: MD5-only node still works.
static void demo_md5_fallback()
{
  section("4. BACKWARDS COMPAT: MD5-only challenge still accepted");
  const http::login user{"foo", "bar"};
  http::http_server_auth server{user, test_rng};
  http::http_client_auth client{user};

  http::http_request_info request{};
  request.m_http_method_str = "GET";
  request.m_URI = "/legacy";

  auto challenge = server.get_response(request);
  challenge->m_header_info.m_etc_fields = challenge->m_additional_fields;

  std::list<std::pair<std::string, std::string>> md5_only;
  for (const auto& entry : challenge->m_header_info.m_etc_fields)
    if (iequals(parse_auth(entry.second).at("algorithm").substr(0, 3), "MD5"))
      md5_only.push_back(entry);

  http::http_response_info md5_challenge{};
  md5_challenge.m_header_info.m_etc_fields = md5_only;
  CHECK(client.handle_401(md5_challenge) == http::http_client_auth::kSuccess);

  const auto auth_field = client.get_auth_field(request.m_http_method_str, request.m_URI);
  std::printf("  Authorization: %s\n", auth_field->second.c_str());
  CHECK(iequals(parse_auth(auth_field->second).at("algorithm"), "MD5"));
  request.m_header_info.m_etc_fields.push_back(*auth_field);
  CHECK(!server.get_response(request).is_initialized());
}

int main()
{
  std::printf("monero-gui SHA-256 HTTP Digest Auth evidence (RFC 7616 / PR #11345)\n");
  demo_server_challenges();
  demo_client_sha256();
  demo_dogfood_replay();
  demo_md5_fallback();

  std::printf("\n================ SUMMARY ================\n");
  std::printf("%d passed, %d failed\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
