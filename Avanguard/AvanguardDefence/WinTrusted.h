#pragma once

#include <Windows.h>
#include <WinTrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

BOOL IsFileSigned(LPCWSTR FilePath, BOOL CheckRevocation);
BOOL VerifyEmbeddedSignature(LPCWSTR FilePath);
BOOL GetCertInfo(LPCWSTR FilePath);