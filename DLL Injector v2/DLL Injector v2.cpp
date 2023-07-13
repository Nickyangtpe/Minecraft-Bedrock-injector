#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <psapi.h>
#include <VersionHelpers.h>
#include <atlstr.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <conio.h>
#include <iostream>

DWORD GetMinecraftProcessID()
{

    DWORD processID = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, L"Minecraft.Windows.exe") == 0)
            {
                processID = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processID;
}

BOOL InjectDLL(DWORD ProcessID, LPCSTR dllPath, const std::string& language)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

    if (hProcess)
    {
        LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
        if (pRemotePath)
        {
            if (WriteProcessMemory(hProcess, pRemotePath, dllPath, strlen(dllPath) + 1, NULL))
            {
                HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                if (hKernel32)
                {
                    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
                    if (pLoadLibraryA)
                    {
                        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemotePath, 0, NULL);
                        if (hThread)
                        {
                            WaitForSingleObject(hThread, INFINITE);
                            CloseHandle(hThread);
                            CloseHandle(hProcess);
                            return TRUE;
                        }
                    }
                }
            }
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        }
        CloseHandle(hProcess);
    }

    return FALSE;
}


int main()
{
    std::string language;
    std::ifstream languageFile("language.txt");

    if (languageFile.is_open())
    {
        std::getline(languageFile, language);
        languageFile.close();
    }

    if (language.empty())
    {
        std::cout << "\n\n\n\n\n\n\n\n\n\nSelect language:" << std::endl;
        std::cout << "1. Chinese (繁體)" << std::endl;
        std::cout << "2. Chinese (簡體)" << std::endl;
        std::cout << "3. English" << std::endl;
        std::cout << "4. Japanese" << std::endl;
        std::cout << "5. Korean" << std::endl;

        int languageChoice;
        std::cin >> languageChoice;

        switch (languageChoice)
        {
        case 1:
            language = "Chinese (繁體)";
            break;
        case 2:
            language = "Chinese (簡體)";
            break;
        case 3:
            language = "English";
            break;
        case 4:
            language = "Japanese";
            break;
        case 5:
            language = "Korean";
            break;
        default:
            std::cout << "Invalid choice." << std::endl;
            language = "";
        }

        std::ofstream languageOutputFile("language.txt");
        if (languageOutputFile.is_open())
        {
            languageOutputFile << language;
            languageOutputFile.close();
        }
    }

    if (IsWindowsXPOrGreater())
    {

        std::string minecraftProcessSearch;
        std::string minecraftProcessNotFound;
        std::string chooseDllFile;
        std::string tryingToInject;
        std::string dllInjectionSuccess;
        std::string dllInjectionFailure;
        std::string noDllFileSelected;
        std::string Menu;

        if (language == "English")
        {
            minecraftProcessSearch = "Searching for Minecraft process...";
            minecraftProcessNotFound = "Minecraft process not found.";
            chooseDllFile = "Choose DLL file...";
            tryingToInject = "Trying to inject DLL: ";
            dllInjectionSuccess = "DLL injection successful.";
            dllInjectionFailure = "DLL injection failed.";
            noDllFileSelected = "No DLL file selected.";
            Menu = "\nSelected language: " + language + "\nSelect an option: \n1. Inject DLL\n2. Select language\n3. Exit";
        }
        else if (language == "Japanese")
        {
            minecraftProcessSearch = "Minecraftプロセスを検索中...";
            minecraftProcessNotFound = "Minecraftプロセスが見つかりませんでした。";
            chooseDllFile = "DLLファイルを選択してください...";
            tryingToInject = "DLLを注入中: ";
            dllInjectionSuccess = "DLLの注入に成功しました。";
            dllInjectionFailure = "DLLの注入に失敗しました。";
            noDllFileSelected = "DLLファイルが選択されていません。";
            Menu = "\n選択された言語：" + language + "\nオプションを選択してください：\n1.DLLのインジェクション\n2.言語の選択\n3.終了";
        }
        else if (language == "Korean")
        {
            minecraftProcessSearch = "Minecraft 프로세스 검색 중...";
            minecraftProcessNotFound = "Minecraft 프로세스를 찾을 수 없습니다.";
            chooseDllFile = "DLL 파일 선택...";
            tryingToInject = "DLL 주입 시도 중: ";
            dllInjectionSuccess = "DLL 주입 성공.";
            dllInjectionFailure = "DLL 주입 실패.";
            noDllFileSelected = "DLL 파일이 선택되지 않았습니다.";
            Menu = "\n선택한 언어: " + language + "\n옵션을 선택하세요: \n1. DLL 삽입\n2. 언어 선택\n3. 종료";
        }
        else if (language == "Chinese (繁體)")
        {
            minecraftProcessSearch = "尋找 Minecraft 進程....";
            minecraftProcessNotFound = "Minecraft 進程未找到.";
            chooseDllFile = "挑選DLL中...";
            tryingToInject = "正在嘗試注入 DLL : ";
            dllInjectionSuccess = "DLL 注入成功.";
            dllInjectionFailure = "DLL 注入失敗.";
            noDllFileSelected = "未選擇 DLL.";
            Menu = "\n所選的語言：" + language + "\n選擇一個選項：\n1.注入DLL\n2.選擇語言\n3.退出";
        }
        else if (language == "Chinese (簡體)")
        {
            minecraftProcessSearch = "寻找 Minecraft 进程....";
            minecraftProcessNotFound = "Minecraft 进程找到.";
            chooseDllFile = "挑选DLL中...";
            tryingToInject = "正在尝试注入 DLL : ";
            dllInjectionSuccess = "DLL 注入成功.";
            dllInjectionFailure = "DLL 注入失败.";
            noDllFileSelected = "未选择 DLL.";
            Menu = "\n所选的语言：" + language + "\n选择一个选项：\n1.注入DLL\n2.选择语言\n3.退出";
        }

        while (true)
        {
            if (language.empty())
            {
                std::cout << "Language not selected." << std::endl;
            }

            std::cout << Menu << std::endl;

            int option;
            std::cin >> option;
            
            switch (option)
            {
            default:
            {
                std::cout << "\nPlease enter the correct number\n" << std::endl;
                system("pause");
                system("cls");
                break;
            }
            case 1:
            {
                std::cout << "Inject DLL" << std::endl;

                std::cout << minecraftProcessSearch << std::endl;
                DWORD PID = GetMinecraftProcessID();
                if (PID == 0)
                {
                    std::cout << minecraftProcessNotFound << std::endl;
                }
                else
                {
                    std::cout << chooseDllFile << std::endl;

                    OPENFILENAMEA ofn;
                    CHAR szFile[MAX_PATH] = { 0 };

                    ZeroMemory(&ofn, sizeof(ofn));
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = NULL;
                    ofn.lpstrFilter = "Dynamic Link Libraries (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
                    ofn.lpstrFile = szFile;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

                    if (GetOpenFileNameA(&ofn))
                    {
                        std::cout << tryingToInject << ofn.lpstrFile << std::endl;
                        if (InjectDLL(PID, ofn.lpstrFile, language))
                        {
                            std::cout << dllInjectionSuccess << std::endl;
                        }
                        else
                        {
                            std::cout << dllInjectionFailure << std::endl;
                        }
                    }
                    else
                    {
                        std::cout << noDllFileSelected << std::endl;
                    }
                }

                break;
            }
           
            case 2:
            {
                std::cout << "\n\nSelect language:" << std::endl;
                std::cout << "1. Chinese (繁體)" << std::endl;
                std::cout << "2. Chinese (簡體)" << std::endl;
                std::cout << "3. English" << std::endl;
                std::cout << "4. Japanese" << std::endl;
                std::cout << "5. Korean" << std::endl;

                int languageChoice;
                std::cin >> languageChoice;

                switch (languageChoice)
                {
                case 1:
                    language = "Chinese (繁體)";
                    break;
                case 2:
                    language = "Chinese (簡體)";
                    break;
                case 3:
                    language = "English";
                    break;
                case 4:
                    language = "Japanese";
                    break;
                case 5:
                    language = "Korean";
                    break;
                default:
                    std::cout << "Invalid choice." << std::endl;
                    language = "";
                }

                std::ofstream languageOutputFile("language.txt");
                if (languageOutputFile.is_open())
                {
                    languageOutputFile << language;
                    languageOutputFile.close();
                }
                if (language == "English")
                {
                    minecraftProcessSearch = "Searching for Minecraft process...";
                    minecraftProcessNotFound = "Minecraft process not found.";
                    chooseDllFile = "Choose DLL file...";
                    tryingToInject = "Trying to inject DLL: ";
                    dllInjectionSuccess = "DLL injection successful.";
                    dllInjectionFailure = "DLL injection failed.";
                    noDllFileSelected = "No DLL file selected.";
                    Menu = "Selected language: " + language + "\nSelect an option: \n1. Inject DLL\n2. Select language\n3. Exit\n";
                }
                else if (language == "Japanese")
                {
                    minecraftProcessSearch = "Minecraftプロセスを検索中...";
                    minecraftProcessNotFound = "Minecraftプロセスが見つかりませんでした。";
                    chooseDllFile = "DLLファイルを選択してください...";
                    tryingToInject = "DLLを注入中: ";
                    dllInjectionSuccess = "DLLの注入に成功しました。";
                    dllInjectionFailure = "DLLの注入に失敗しました。";
                    noDllFileSelected = "DLLファイルが選択されていません。";
                    Menu = "選択された言語：" + language + "\nオプションを選択してください：\n1.DLLのインジェクション\n2.言語の選択\n3.終了\n";
                }
                else if (language == "Korean")
                {
                    minecraftProcessSearch = "Minecraft 프로세스 검색 중...";
                    minecraftProcessNotFound = "Minecraft 프로세스를 찾을 수 없습니다.";
                    chooseDllFile = "DLL 파일 선택...";
                    tryingToInject = "DLL 주입 시도 중: ";
                    dllInjectionSuccess = "DLL 주입 성공.";
                    dllInjectionFailure = "DLL 주입 실패.";
                    noDllFileSelected = "DLL 파일이 선택되지 않았습니다.";
                    Menu = "선택한 언어: " + language + "\n옵션을 선택하세요: \n1. DLL 삽입\n2. 언어 선택\n3. 종료\n";
                }
                else if (language == "Chinese (繁體)")
                {
                    minecraftProcessSearch = "尋找 Minecraft 進程....";
                    minecraftProcessNotFound = "Minecraft 進程未找到.";
                    chooseDllFile = "挑選DLL中...";
                    tryingToInject = "正在嘗試注入 DLL : ";
                    dllInjectionSuccess = "DLL 注入成功.";
                    dllInjectionFailure = "DLL 注入失敗.";
                    noDllFileSelected = "未選擇 DLL.";
                    Menu = "所選的語言：" + language + "\n選擇一個選項：\n1.注入DLL\n2.選擇語言\n3.退出\n";
                }
                else if (language == "Chinese (簡體)")
                {
                    minecraftProcessSearch = "寻找 Minecraft 进程....";
                    minecraftProcessNotFound = "Minecraft 进程找到.";
                    chooseDllFile = "挑选DLL中...";
                    tryingToInject = "正在尝试注入 DLL : ";
                    dllInjectionSuccess = "DLL 注入成功.";
                    dllInjectionFailure = "DLL 注入失败.";
                    noDllFileSelected = "未选择 DLL.";
                    Menu = "所选的语言：" + language + "\n选择一个选项：\n1.注入DLL\n2.选择语言\n3.退出";
                }
                std::string Menu;
            }

            }

        }
    }

    return 0;
}
