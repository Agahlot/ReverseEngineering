#include<stdio.h>
#include<windows.h>

BOOL SeDebugPrivilege(HANDLE hHandle) {

HANDLE hToken;
DWORD dwSize;
TOKEN_PRIVILEGES newPriv, oldPriv;
LUID luid;

if(!OpenProcessToken(hHandle, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)) {
    printf("[-] OpenProcessToken() error : %d", GetLastError());
    return FALSE;
}

if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
    printf("[-] LookupPrivilegeValue() error : %d", GetLastError());
    return FALSE;
}

newPriv.PrivilegeCount = 1;
newPriv.Privileges[0].Luid = luid;
newPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

if(ERROR_NOT_ALL_ASSIGNED == AdjustTokenPrivileges(hToken, FALSE, &newPriv, sizeof(TOKEN_PRIVILEGES), &oldPriv, &dwSize)) {
    printf("[-] AdjustTokenPrivileges() error", GetLastError());
    return FALSE;
}

LPSTR bName;
LookupPrivilegeName(NULL, &newPriv.Privileges[0].Luid, bName, &dwSize);
bName = malloc(dwSize + 1);
LookupPrivilegeName(NULL, &newPriv.Privileges[0].Luid, bName, &dwSize);
printf("[+] SE_PRIVILEGE_ENABLED : %s", bName);
free(bName);

CloseHandle(hToken);
return TRUE;
}

void main() {
    SeDebugPrivilege(GetCurrentProcess());
}
