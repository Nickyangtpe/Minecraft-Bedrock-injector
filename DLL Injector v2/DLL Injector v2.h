#pragma once

#include <Windows.h>

BOOL InjectDLL(DWORD ProcessID);
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam);
int main();
