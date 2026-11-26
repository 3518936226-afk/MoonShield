/* MoonShield Windows argument-preserving launcher. Apache-2.0.
 * Audit, normalization, reports and conformance logic live in MoonBit/Wasm.
 * No shell expression evaluation or candidate-script execution occurs here.
 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static wchar_t command[32768];
static size_t used;
static int append(wchar_t c) {
  if (used >= 32766) return 0;
  command[used++] = c; command[used] = 0; return 1;
}
static int quoted(const wchar_t *arg) {
  size_t slash = 0;
  if (used && !append(L' ')) return 0;
  if (!append(L'"')) return 0;
  for (; *arg; ++arg) {
    if (*arg == L'\\') { ++slash; continue; }
    size_t n = (*arg == L'"') ? slash * 2 + 1 : slash;
    while (n--) if (!append(L'\\')) return 0;
    slash = 0;
    if (!append(*arg)) return 0;
  }
  slash *= 2;
  while (slash--) if (!append(L'\\')) return 0;
  return append(L'"');
}
int wmain(int argc, wchar_t **argv) {
  wchar_t root[32768], host[32768], script[32768];
  DWORD size = GetModuleFileNameW(NULL, root, 32768);
  if (!size || size >= 32768) return 2;
  wchar_t *end = wcsrchr(root, L'\\');
  if (!end) return 2;
  *end = 0;
  if (wcslen(root) + 32 >= 32768) return 2;
  swprintf(script, 32768, L"%ls\\scripts\\launch.ps1", root);
  size = GetSystemDirectoryW(host, 32768);
  if (!size || size + 64 >= 32768) return 2;
  wcscat(host, L"\\WindowsPowerShell\\v1.0\\powershell.exe");
  if (!quoted(host) || !quoted(L"-NoProfile") || !quoted(L"-ExecutionPolicy") ||
      !quoted(L"Bypass") || !quoted(L"-File") || !quoted(script)) return 2;
  for (int i = 1; i < argc; ++i) if (!quoted(argv[i])) return 2;
  STARTUPINFOW startup = {0};
  PROCESS_INFORMATION process = {0};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  if (!CreateProcessW(host, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                      NULL, NULL, &startup, &process)) {
    fprintf(stderr, "MoonShield launcher failed (Windows error %lu)\n", GetLastError());
    return 2;
  }
  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD result = 2;
  GetExitCodeProcess(process.hProcess, &result);
  CloseHandle(process.hThread); CloseHandle(process.hProcess);
  return (int)result;
}
