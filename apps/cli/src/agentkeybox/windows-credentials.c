#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <wincred.h>
#include <wtsapi32.h>

#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

enum {
    SCREEN_LOCKED = 4,
    SCREEN_UNKNOWN = 5,
    UNSAFE_DIRECTORY = 7,
    NOT_FOUND = 44,
    BAD_ARGUMENT = 64,
    STORE_ERROR = 70,
    KEY_LENGTH = 88
};

static TOKEN_USER *read_token_user(void)
{
    HANDLE token;
    DWORD size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return NULL;
    }

    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    TOKEN_USER *user = size ? LocalAlloc(LPTR, size) : NULL;
    if (user && !GetTokenInformation(token, TokenUser, user, size, &size)) {
        LocalFree(user);
        user = NULL;
    }
    CloseHandle(token);
    return user;
}

static int session_owner(const WTSINFOEX_LEVEL1_W *info, PSID process_sid)
{
    if (!info->UserName[0]) {
        return SCREEN_LOCKED;
    }
    WCHAR account[512], domain[512];
    if (swprintf(account, ARRAYSIZE(account), L"%ls%ls%ls", info->DomainName,
                 info->DomainName[0] ? L"\\" : L"", info->UserName) < 0) {
        return SCREEN_UNKNOWN;
    }
    BYTE session_sid[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(session_sid), domain_size = ARRAYSIZE(domain);
    SID_NAME_USE use;
    if (!LookupAccountNameW(NULL, account, session_sid, &sid_size, domain, &domain_size, &use)) {
        return SCREEN_UNKNOWN;
    }
    return EqualSid(process_sid, session_sid) ? 0 : SCREEN_LOCKED;
}

static int screen_state(PSID process_sid)
{
    DWORD session_id, size;
    LPWSTR buffer;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session_id)) {
        return SCREEN_UNKNOWN;
    }
    if (session_id == 0) {
        return SCREEN_LOCKED; /* Services have no user desktop. */
    }
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session_id,
                                     WTSSessionInfoEx, &buffer, &size)) {
        return SCREEN_UNKNOWN;
    }

    int state = SCREEN_UNKNOWN;
    const WTSINFOEXW *session = (const WTSINFOEXW *)buffer;
    if (size >= sizeof(*session) && session->Level == 1) {
        const WTSINFOEX_LEVEL1_W *info = &session->Data.WTSInfoExLevel1;
        if (info->SessionId == session_id) {
            if (info->SessionState != WTSActive || info->SessionFlags == WTS_SESSIONSTATE_LOCK) {
                state = SCREEN_LOCKED;
            } else if (info->SessionFlags == WTS_SESSIONSTATE_UNLOCK) {
                /* A Run As process can have a different SID in this same session. */
                state = session_owner(info, process_sid);
            }
        }
    }
    WTSFreeMemory(buffer);
    if (state != 0) {
        return state;
    }

    /* Refuse the lock screen and other secure desktops even during a WTS transition. */
    HDESK desktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!desktop) {
        return SCREEN_UNKNOWN;
    }
    WCHAR name[256];
    BOOL known = GetUserObjectInformationW(desktop, UOI_NAME, name, sizeof(name), NULL);
    CloseDesktop(desktop);
    if (!known) {
        return SCREEN_UNKNOWN;
    }
    return _wcsicmp(name, L"Default") == 0 ? 0 : SCREEN_LOCKED;
}

static BOOL private_path(WCHAR *path, PSID user_sid, BOOL directory, BOOL may_be_missing)
{
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        return may_be_missing && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (!!(attributes & FILE_ATTRIBUTE_DIRECTORY) != directory)) {
        return FALSE;
    }

    /* Node's POSIX mode bits do not protect Windows logon tokens. Check the inherited DACL. */
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD result = GetNamedSecurityInfoW(path, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, NULL, &dacl, NULL, &descriptor);
    BOOL safe = result == ERROR_SUCCESS && owner && dacl && EqualSid(owner, user_sid);
    for (DWORD i = 0; safe && i < dacl->AceCount; i++) {
        PVOID raw_ace;
        safe = GetAce(dacl, i, &raw_ace);
        if (!safe) {
            break;
        }
        const ACE_HEADER *header = raw_ace;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            const ACCESS_ALLOWED_ACE *ace = raw_ace;
            PSID sid = (PSID)&ace->SidStart;
            safe = EqualSid(sid, user_sid) || IsWellKnownSid(sid, WinLocalSystemSid) ||
                   IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
                   ((header->AceFlags & INHERIT_ONLY_ACE) && IsWellKnownSid(sid, WinCreatorOwnerSid));
        } else if (header->AceType != ACCESS_DENIED_ACE_TYPE) {
            safe = FALSE;
        }
    }
    LocalFree(descriptor);
    return safe;
}

static BOOL valid_key(const BYTE *key, DWORD size)
{
    if (size != KEY_LENGTH || key[86] != '=' || key[87] != '=') {
        return FALSE;
    }
    for (size_t i = 0; i < 86; i++) {
        BYTE ch = key[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '+' || ch == '/')) {
            return FALSE;
        }
    }
    return TRUE;
}

static int read_key(WCHAR *target, PSID sid)
{
    PCREDENTIALW credential;
    if (!CredReadW(target, CRED_TYPE_GENERIC, 0, &credential)) {
        return GetLastError() == ERROR_NOT_FOUND ? NOT_FOUND : STORE_ERROR;
    }
    int result = STORE_ERROR;
    if (valid_key(credential->CredentialBlob, credential->CredentialBlobSize)) {
        result = screen_state(sid);
        if (result == 0) {
            DWORD written = 0;
            if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), credential->CredentialBlob,
                           credential->CredentialBlobSize, &written, NULL) || written != KEY_LENGTH) {
                result = STORE_ERROR;
            }
        }
    }
    SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
    CredFree(credential);
    return result;
}

static int save_key(WCHAR *target, PSID sid)
{
    BYTE key[KEY_LENGTH + 1];
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
        return STORE_ERROR;
    }
    DWORD size = (DWORD)fread(key, 1, sizeof(key), stdin);
    int result = BAD_ARGUMENT;
    if (!ferror(stdin) && valid_key(key, size)) {
        result = screen_state(sid);
        if (result == 0) {
            CREDENTIALW credential = {0};
            credential.Type = CRED_TYPE_GENERIC;
            credential.TargetName = target;
            credential.CredentialBlob = key;
            credential.CredentialBlobSize = size;
            credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
            result = CredWriteW(&credential, 0) ? 0 : STORE_ERROR;
        }
    }
    SecureZeroMemory(key, sizeof(key));
    return result;
}

static int handle_command(int argc, WCHAR **argv, PSID sid)
{
    int state = screen_state(sid);
    if (state != 0 || (argc == 2 && wcscmp(argv[1], L"screen") == 0)) {
        return state;
    }
    if (argc == 7 && wcscmp(argv[1], L"check-profile") == 0) {
        for (int i = 2; i < argc; i++) {
            if (!private_path(argv[i], sid, i != 6, i >= 5)) {
                return UNSAFE_DIRECTORY;
            }
        }
        return 0;
    }
    if (argc != 3 || wcslen(argv[2]) != 64 || wcsspn(argv[2], L"0123456789abcdef") != 64) {
        return BAD_ARGUMENT;
    }

    WCHAR target[96];
    if (swprintf(target, ARRAYSIZE(target), L"dev.agentkeybox.session.v1/%ls", argv[2]) < 0) {
        return BAD_ARGUMENT;
    }
    if (wcscmp(argv[1], L"read") == 0) {
        return read_key(target, sid);
    }
    if (wcscmp(argv[1], L"save") == 0) {
        return save_key(target, sid);
    }
    if (wcscmp(argv[1], L"remove") == 0) {
        return CredDeleteW(target, CRED_TYPE_GENERIC, 0) || GetLastError() == ERROR_NOT_FOUND
            ? 0 : STORE_ERROR;
    }
    return BAD_ARGUMENT;
}

int wmain(int argc, WCHAR **argv)
{
    TOKEN_USER *user = read_token_user();
    if (!user) {
        return SCREEN_UNKNOWN;
    }
    int result = handle_command(argc, argv, user->User.Sid);
    LocalFree(user);
    return result;
}
