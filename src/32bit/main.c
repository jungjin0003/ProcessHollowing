#include "ProcessHollowing.h"

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdParam, int nCmdShow)
{
    ProcessHollowing("C:\\Windows\\SysWOW64\\svchost.exe", "MessageBox.exe");
}