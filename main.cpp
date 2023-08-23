#include <winsock2.h>
#include <windows.h>
#include <cstdio>
#include <psapi.h>

#pragma comment(lib, "ws2_32.lib")

/* Login address from the game */
char loginAddress[15];

/* brief: Open a process by its name
 * param: processName Name of the process to be opened
 * return: Handle to the opened process, or nullptr if not found
 */
HANDLE OpenProcessByName(const char* processName)
{
    DWORD processes[1024];
    DWORD bytesReturned;

    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned))
    {
        printf("EnumProcesses failed\n");
        return nullptr;
    }

    DWORD numProcesses = bytesReturned / sizeof(DWORD);

    for (DWORD i = 0; i < numProcesses; i++)
    {
        DWORD processId = processes[i];
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, processId);

        if (hProcess) {
            char processNameBuffer[MAX_PATH];
            if (GetModuleBaseName(hProcess, NULL, processNameBuffer, sizeof(processNameBuffer)))
            {
                if (strcmp(processNameBuffer, processName) == 0)
                {
                    return hProcess;
                }
            }

            CloseHandle(hProcess);
        }
    }

    return nullptr;
}

/* brief: Get the base address of the executable module
 * param: hProcess Handle to the target process
 * return: Base address of the executable module, or 0 if not found
 */
uintptr_t GetExecutableBaseAddress(HANDLE hProcess)
{
    HMODULE hModule;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded))
    {
        MODULEINFO moduleInfo;
        if (GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO)))
        {
            return (uintptr_t)moduleInfo.lpBaseOfDll;
        }
    }

    return 0;
}

/* brief: Replace the login address in the game process
 * param: hProcess Handle to the game process
 */
void ReplaceLoginAddress(HANDLE hProcess)
{
    const char* localLoginAddress = "127.0.0.1";

    const uintptr_t moduleBaseAddress = GetExecutableBaseAddress(hProcess);
    const uintptr_t loginAddressPtr = moduleBaseAddress + 0x00732FB0;

    ReadProcessMemory(hProcess, (LPVOID)loginAddressPtr, loginAddress, sizeof(loginAddress), nullptr);

    printf("[ReplaceLoginAddress] Replacing login address <%s> with <%s>\n", loginAddress, localLoginAddress);
    WriteProcessMemory(hProcess, (LPVOID)loginAddressPtr, localLoginAddress, strlen(localLoginAddress) + 1, nullptr);
    printf("[ReplaceLoginAddress] Successfully replaced the login address!\n");
}

/* brief: Create a proxy server
 * param: port Port number for the proxy server
 * return: True if the proxy was created successfully, false otherwise
 */
bool CreateProxy(int port)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        printf("Listen failed.\n");
        closesocket(listenSocket);
        WSACleanup();
        return false;
    }

    printf("[CreateProxy] Socket created and listening on port %d\n", port);

    while (true)
    {
        SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
        printf("[Proxy] New client connected successfully\n");

        SOCKET upstreamSocket = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in upstreamAddr;
        upstreamAddr.sin_family = AF_INET;
        upstreamAddr.sin_port = htons(11000);
        upstreamAddr.sin_addr.s_addr = inet_addr(loginAddress);

        if (connect(upstreamSocket, (sockaddr*)&upstreamAddr, sizeof(upstreamAddr)) == SOCKET_ERROR)
        {
            printf("[Proxy] Failed to connect to the upstream server.\n");
            closesocket(upstreamSocket);
            closesocket(clientSocket);
            return false;
        }

        printf("[Proxy] Successfully connected to the upstream server.\n");

        while (true)
        {

            char buffer[1024];

            // Receive packets from the client
            int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);

            if (bytesRead <= 0)
            {
                break; // Client disconnected or error
            }

            printf("[Received from client] ");
            for (int i = 0; i < bytesRead; i++)
            {
                printf("%02X ", (unsigned char)buffer[i]);
            }
            printf("\n");

            // Send packet to the upstream server
            send(upstreamSocket, buffer, bytesRead, 0);

            int totalBytesReceived = 0;
            int minimumPacketLength = 80; /* Login packet length, I am not going to tlv16 parsing yet */

            char bufferrecv[minimumPacketLength];

            /* Receive packet from the upstream server */
            while (totalBytesReceived < minimumPacketLength)
            {
                int bytesReceived = recv(upstreamSocket, bufferrecv + totalBytesReceived, sizeof(bufferrecv) - totalBytesReceived, 0);

                if (bytesReceived <= 0)
                {
                    printf("[Proxy] Upstream disconnected or error while receiving.\n");
                    break;
                }

                totalBytesReceived += bytesReceived;
            }

            printf("[Received from upstream] ");
            for (int i = 0; i < totalBytesReceived; i++)
            {
                printf("%02X ", (unsigned char)bufferrecv[i]);
            }
            printf("\n");

            // Send packet from the upstream server back to our client
            send(clientSocket, bufferrecv, totalBytesReceived, 0);
        }

        closesocket(upstreamSocket);

    }

    closesocket(listenSocket);
    WSACleanup();
    return true;
}

/* brief: Main entry point of the program */
int main()
{
    HANDLE hProcess = OpenProcessByName("ohka.dat");

    if (!hProcess)
    {
        printf("[Main] Unable to find the process for Bots. Please ensure the game is running. Quitting.\n");
        return 0;
    }

    ReplaceLoginAddress(hProcess);
    CreateProxy(11000);

    return 0;
}
