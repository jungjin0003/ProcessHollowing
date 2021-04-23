#include "ProcessHollowing.h"

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdParam, int nCmdShow)
{
    ProcessHollowing("explorer.exe", "MessageBox.exe");
}