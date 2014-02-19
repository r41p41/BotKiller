BOOL DebugPriv(BOOL val)
{
    HANDLE token;
    TOKEN_PRIVILEGES priv;
    BOOL ret = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        priv.PrivilegeCount = 1;
        if(val)
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        else
        priv.Privileges[0].Attributes = 0;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid) != FALSE &&
            AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE) {
                ret = TRUE;
        }

        CloseHandle(token);
    }

    return ret;
}
