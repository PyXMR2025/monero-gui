# Reproducible build + evidence run for SHA-256 Digest Auth (PR #11345 backport)
# Requires: VS 2022 (cl.exe), Boost + OpenSSL headers/libs.
# Adjust $Ana if your OpenSSL/Boost prefix differs.
$ErrorActionPreference = "Stop"

$Root   = "z:\workspace\monero-gui"
$Epee   = "$Root\monero\contrib\epee"
$Ext    = "$Root\monero\external\easylogging++"
$Ana    = "C:\Users\zhang\anaconda3\Library"
$Out    = "$Root\build-auth-test"
$Log    = "$Out\sha256-evidence.log"

Remove-Item $Log -ErrorAction SilentlyContinue
function Log($s) { $s | Tee-Object -FilePath $Log -Append | Out-Host }

Log "==============================================================="
Log " monero-gui SHA-256 HTTP Digest Auth - build/run evidence"
Log " Date (UTC): $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))"
Log "==============================================================="

# --- 1. prove WHICH source tree / patch state is being compiled -------------
Push-Location "$Root\monero"
Log "`n[submodule] git describe:"
Log ((git rev-parse HEAD) -join "")
Log "`n[submodule] working-tree patch applied for PR #11345:"
Log ((git diff --stat) -join "`n")
Log "`n[submodule] digest algorithm tuple in the compiled source:"
Log ((Select-String -Path "$Epee\src\http_auth.cpp" -Pattern 'digest_algorithms\{\}|struct sha256_|struct md5_ ') -join "`n")
Pop-Location

Log "`n[hash] SHA256 of the compiled auth sources:"
foreach ($f in @("$Epee\src\http_auth.cpp", "$Epee\include\net\http_auth.h")) {
  $h = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
  Log "  $h  $(Split-Path $f -Leaf)"
}

# --- 2. environment -----------------------------------------------------------
$vsShell = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1"
. $vsShell -Arch amd64 -SkipAutomaticLocation | Out-Null
Log "`n[toolchain] $((cl 2>&1 | Select-Object -First 1))"
Log "[openssl]   $((Select-String "$Ana\include\openssl\opensslv.h" -Pattern 'OPENSSL_VERSION_TEXT').Line.Trim())"
Log "[boost]     BOOST_VERSION = $((Select-String "$Ana\include\boost\version.hpp" -Pattern '#define BOOST_VERSION ').Line.Trim())"

# --- 3. prepare a compile copy of the REAL source -----------------------------
# The shipped source targets the project's MinGW/older-Boost toolchain.
# Under Boost 1.82 + MSVC exactly TWO compile-only adaptations are needed
# (identical runtime semantics); apply them to a COPY and show the diff:
$real = Get-Content "$Epee\src\http_auth.cpp" -Raw
$copy = $real.
  Replace('const boost::iterator_range<const char*> data(boost::as_literal(arg));',
          'const auto data = boost::as_literal(arg);').
  Replace('reinterpret_cast<const std::uint8_t*>(data.begin())',
          'reinterpret_cast<const std::uint8_t*>(&*data.begin())')
Set-Content "$Out\http_auth_testcopy.cpp" $copy -Encoding UTF8
Log "`n[compat] diff between shipped http_auth.cpp and the MSVC/Boost1.82 compile copy:"
$d = git diff --no-index --ignore-all-space `
  "$Epee\src\http_auth.cpp" "$Out\http_auth_testcopy.cpp" 2>&1
Log (($d | Select-String '^[-+]' | Where-Object { $_ -notmatch '^[-+]{3}' }) -join "`n")

# --- 4. compile + link --------------------------------------------------------
Push-Location $Out
Remove-Item *.obj, auth_test.exe -ErrorAction SilentlyContinue
$flags = @("/nologo","/std:c++17","/EHsc","/O2","/W3",
           "/DNOMINMAX","/D__thread=thread_local","/D_CRT_SECURE_NO_WARNINGS",
           "/I$Out\shim","/I$Epee\include","/I$Ext","/I$Ana\include","/c")
$sources = @(
  "$Out\http_auth_testcopy.cpp|http_auth.obj",
  "$Epee\src\wipeable_string.cpp|wipeable_string.obj",
  "$Epee\src\hex.cpp|hex.obj",
  "$Out\elpp_init.cpp|elpp_init.obj",
  "$Ext\easylogging++.cc|easylogging.obj",
  "$Out\test_main.cpp|test_main.obj"
)
foreach ($pair in $sources) {
  $src, $obj = $pair.Split("|")
  Log "`n[compile] $(Split-Path $src -Leaf)"
  $err = cl @flags $src "/Fo$obj" 2>&1 | Select-String 'error|fatal'
  if ($err) { $err | ForEach-Object { Log $_ }; throw "compile failed: $src" }
}
Log "`n[link] auth_test.exe"
$linkErr = link /nologo http_auth.obj wipeable_string.obj hex.obj test_main.obj `
  elpp_init.obj easylogging.obj "/LIBPATH:$Ana\lib" libcrypto.lib /OUT:auth_test.exe 2>&1
if ($linkErr) { $linkErr | ForEach-Object { Log $_ }; throw "link failed" }
Log "  OK"

# --- 5. run -------------------------------------------------------------------
$env:PATH = "$Ana\bin;$env:PATH"
Log "`n[run] auth_test.exe`n"
$run = & "$Out\auth_test.exe" 2>&1
Log ($run -join "`n")
$code = $LASTEXITCODE
Pop-Location

Log "`nLog saved to: $Log"
if ($code -ne 0) { throw "auth_test.exe reported failures (exit $code)" }
Log "RESULT: SUCCESS"
