#include "stdafx.h"
#include "CodepageAPI.h"

using namespace std;

string WideToAnsi(const wstring &WideString, WORD CodePage) {
	if (WideString.empty()) return string();

	int Length = WideCharToMultiByte(
		CodePage,
		WC_COMPOSITECHECK | WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR,
		WideString.c_str(),
		-1,
		NULL,
		0,
		NULL,
		NULL
	);

	if (Length == 0) return string();

	string Result;
	Result.resize(Length - 1);

	WideCharToMultiByte(
		CodePage,
		WC_COMPOSITECHECK | WC_DISCARDNS | WC_SEPCHARS | WC_DEFAULTCHAR,
		WideString.c_str(),
		-1,
		(LPSTR)Result.c_str(),
		Length - 1,
		NULL,
		NULL
	);

	return Result;
}

wstring AnsiToWide(const string &AnsiString, WORD CodePage) {
	if (AnsiString.empty()) return wstring();

	int Length = MultiByteToWideChar(
		CodePage,
		MB_PRECOMPOSED,
		AnsiString.c_str(),
		-1,
		NULL,
		0
	);

	if (Length == 0) return wstring();

	wstring Result;
	Result.resize(Length - 1);

	MultiByteToWideChar(
		CodePage,
		MB_PRECOMPOSED,
		AnsiString.c_str(),
		-1,
		(LPWSTR)Result.c_str(),
		Length - 1
	);

	return Result;
}

string StrOemToAnsi(const string &String) {
	if (String.empty()) return string();

	unsigned int Length = (unsigned int)String.length();

	string Result;
	Result.resize(Length);

	OemToAnsiBuff(String.c_str(), (LPSTR)Result.c_str(), Length);
	return Result;
}

string StrAnsiToOem(const string &String) {
	if (String.empty()) return string();

	unsigned int Length = (unsigned int)String.length();

	string Result;
	Result.resize(Length);

	AnsiToOemBuff(String.c_str(), (LPSTR)Result.c_str(), Length);
	return Result;
}

VOID ConvertToAnsi(LPSTR OEM) {
	OemToAnsi((LPSTR)OEM, OEM);
}

VOID ConvertToOem(LPSTR Ansi) {
	AnsiToOem((LPSTR)Ansi, Ansi);
}