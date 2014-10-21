// connVPN.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "windows.h"
#include "Ras.h"
#include "RasError.h"
#include <iostream>


int CreateVPN(const LPCTSTR pszEntryName, const LPCTSTR pszServerName, 
               const LPCTSTR pszUserName, const LPCTSTR pszPassWord)
{
    RASENTRY rasEntry;
    DWORD dwResult;

    ZeroMemory(&rasEntry, sizeof(rasEntry));
    
    rasEntry.dwCountryCode = 86;
    rasEntry.dwCountryID = 86;
    rasEntry.dwDialExtraPercent = 75;
    rasEntry.dwDialExtraSampleSeconds = 120;
    rasEntry.dwDialMode = RASEDM_DialAll;
    rasEntry.dwType = RASET_Vpn;
    rasEntry.dwRedialCount = 1;
    rasEntry.dwRedialPause = 60;
    rasEntry.dwSize = sizeof(rasEntry);
    rasEntry.dwfOptions = RASEO_SwCompression | RASEO_RequireEncryptedPw | RASEO_RequireDataEncryption | 
        RASEO_PreviewUserPw;
    //rasEntry.dwfOptions = RASEO_SwCompression | RASEO_RequireEncryptedPw | RASEO_RequireDataEncryption;

    rasEntry.dwFramingProtocol = RASFP_Ppp;
    rasEntry.dwVpnStrategy = VS_PptpOnly;
    rasEntry.dwfNetProtocols = RASNP_Ip;
    rasEntry.dwEncryptionType = ET_Optional;    //可选加密
    rasEntry.dwHangUpExtraPercent = 10;
    rasEntry.dwHangUpExtraSampleSeconds = 120;
    lstrcpy(rasEntry.szLocalPhoneNumber, pszServerName);
    lstrcpy(rasEntry.szDeviceType, RASDT_Vpn);
    lstrcpy(rasEntry.szDeviceName, _T("VPN"));

    dwResult = RasSetEntryProperties(NULL, pszEntryName, &rasEntry, sizeof(rasEntry), NULL, 0);
    if (dwResult != 0)
    {
        if( dwResult == ERROR_INVALID_SIZE ) {
            printf("error : SetEntryProperties, size: %d\r\n", sizeof(rasEntry));
            DWORD rasEntrySize = 0;
            RasGetEntryProperties(NULL,NULL,NULL,&rasEntrySize, NULL, NULL);
            rasEntry.dwSize = rasEntrySize > sizeof(RASENTRY) ? sizeof(RASENTRY):rasEntrySize;
            rasEntrySize = rasEntry.dwSize;
            printf("info : SetEntryProperties, rasentry size: %d\r\n", rasEntrySize);
            dwResult = RasSetEntryProperties(NULL, pszEntryName, &rasEntry, rasEntrySize, NULL, 0);
        }
        
        //std::cout<<_T("error : SetEntryProperties, errorno: ")<<dwResult<<"\r\n";
        printf("error : SetEntryProperties, errorno: %d\r\n", dwResult);
        return dwResult;
    }

#if 0
    RASDIALPARAMS rdParams;
    ZeroMemory(&rdParams, sizeof(RASDIALPARAMS));
    rdParams.dwSize = sizeof(RASDIALPARAMS);
    lstrcpy(rdParams.szEntryName, pszEntryName);
    lstrcpy(rdParams.szUserName, pszUserName);
    lstrcpy(rdParams.szPassword, pszPassWord);
    DWORD dwRet = RasSetEntryDialParams(NULL, &rdParams, FALSE);

    if(dwRet == 0)
        return true;
    else
        return false;
#endif
    
    return 0;
}



int GetRasConns(RASCONN** lpRasConn,  LPDWORD lpcConnections){
    DWORD dwCb = sizeof(RASCONN);
    DWORD dwRet = ERROR_SUCCESS;

    printf("GetRasConns, dwCb=%d\r\n", dwCb);

    *lpRasConn = (LPRASCONN) HeapAlloc(GetProcessHeap(), 0, dwCb);
    if (*lpRasConn == NULL){
        printf("HeapAlloc failed!\n");
        return ERROR_ALLOCATING_MEMORY;
    }
    dwRet = RasEnumConnections(*lpRasConn, &dwCb, lpcConnections);

    printf("RasEnumConnections1, ret=%d dwCb=%d connections=%d\r\n", dwRet,dwCb,*lpcConnections);

    if (dwRet == ERROR_BUFFER_TOO_SMALL || dwRet == ERROR_INVALID_SIZE)
    {
        HeapFree(GetProcessHeap(), 0, *lpRasConn);

        *lpRasConn = (LPRASCONN) HeapAlloc(GetProcessHeap(), 0, dwCb);
        if (*lpRasConn == NULL){
            printf("HeapAlloc failed!\n");
            return ERROR_ALLOCATING_MEMORY;
        }
        (*lpRasConn)->dwSize = dwCb;
        dwRet = RasEnumConnections(*lpRasConn, &dwCb, lpcConnections);
    }

    //std::cout<<_T("RasEnumConnections, ret: ")<<dwRet<<"\r\n";
    printf("RasEnumConnections, ret = %d\r\n", dwRet);

    return dwRet;
}

//
//
//
int CheckConnect(const LPCTSTR pszEntryName){
    RASCONN* rasConn;
    //memset(&rasConn,0,sizeof(RASCONN));
    //rasConn.dwSize = 0x19c;

    DWORD dwConnections = 0;

    int ret = GetRasConns(&rasConn, &dwConnections);
    if( ERROR_SUCCESS == ret )
    {
        ret = 1;
        for (DWORD i = 0; i < dwConnections; i++)
        {
            if( _tcscmp((rasConn)[i].szEntryName,pszEntryName) == 0){
                printf("vpn is connected!\r\n");    
                ret = 0;
                break;
            }
        }
    }

    //if (NULL != lpRasConn)
    //{
    //    HeapFree(GetProcessHeap(), 0, lpRasConn);
    //    lpRasConn = NULL;
    //}
    return ret;
}

int CloseVPN(const LPCTSTR pszEntryName){
    DWORD dwCb = sizeof(RASCONN);
    DWORD dwErr = ERROR_SUCCESS;
    DWORD dwRetries = 5;
    DWORD dwConnections = 0;
    RASCONN* lpRasConn = NULL;

    //
    // Loop through in case the information from RAS changes between calls.
    //
    while (dwRetries--)
    {
        //
        // If the memory is allocated, free it.
        //
        if (NULL != lpRasConn)
        {
            HeapFree(GetProcessHeap(), 0, lpRasConn);
            lpRasConn = NULL;
        }
        //
        // Allocate the size needed for the RAS structure.
        //
        lpRasConn = (RASCONN*)HeapAlloc(GetProcessHeap(), 0, dwCb);
        if (NULL == lpRasConn)
        {
            dwErr = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        //
        // Set the structure size for version checking purposes.
        //
        lpRasConn->dwSize = sizeof(RASCONN);
        //
        // Call the RAS API then exit the loop if we are successful or an unknown
        // error occurs.
        //
        dwErr = RasEnumConnections(
            lpRasConn,
            &dwCb,
            &dwConnections);
        if (ERROR_BUFFER_TOO_SMALL != dwErr)
        {
            break;
        }
    }
    //
    // In the success case, print the names of the connections.
    //
    if (ERROR_SUCCESS == dwErr)
    {
        for (DWORD i = 0; i < dwConnections; i++)
        {
            if( _tcscmp(lpRasConn[i].szEntryName,pszEntryName) == 0){
                RasHangUp(lpRasConn[i].hrasconn);
                break;
            }
        }
    }
    else
    {
        printf("RasEnumConnections failed: Error = %d\n", dwErr);
    }
    //
    // Free the memory if necessary.
    //
    if (NULL != lpRasConn)
    {
        HeapFree(GetProcessHeap(), 0, lpRasConn);
        lpRasConn = NULL;
    }
    return dwErr;
}


int DoConnectVPN(const LPCTSTR pszEntryName, const LPCTSTR pszServerName, 
                 const LPCTSTR pszUserName, const LPCTSTR pszPassWord,LPHRASCONN lphRasConn)
{
    RASDIALPARAMS RasDialParams;
    ZeroMemory(&RasDialParams, sizeof(RASDIALPARAMS));
    RasDialParams.dwSize = sizeof(RASDIALPARAMS);
    lstrcpy(RasDialParams.szEntryName, pszEntryName);
    lstrcpy(RasDialParams.szPhoneNumber, pszServerName);
    lstrcpy(RasDialParams.szUserName, pszUserName);
    lstrcpy(RasDialParams.szPassword, pszPassWord);

    DWORD ret = RasDial(NULL, NULL, &RasDialParams, 0, NULL, lphRasConn);
    //std::cout<<_T("RasDial, ret: ")<<ret<<"\r\n";
    printf("RasDial! ret = %d\r\n", ret);
    return ret;
}

int DeleteVPN(const LPCTSTR pszEntryName){
    CloseVPN(pszEntryName);
    int ret = RasDeleteEntry(NULL, pszEntryName);
    if( ret == ERROR_CANNOT_DELETE ){
        HRASCONN hRasConn = NULL;
        DoConnectVPN(pszEntryName,NULL,NULL,NULL,&hRasConn);
        if( NULL != hRasConn ){
            RasHangUp(hRasConn);
            ret = RasDeleteEntry(NULL, pszEntryName);
        }
    }
    return ret;
}

int GetVPN(const LPCTSTR pszEntryName)
{
    DWORD rasEntrySize = 0;
    RASENTRY rasEntry;
    ZeroMemory(&rasEntry, sizeof(RASENTRY));

    int ret = RasGetEntryProperties(NULL,NULL,NULL,&rasEntrySize, NULL, NULL);
    printf("RasGetEntryProperties! EntrySize=%d ret = %d\r\n", rasEntrySize,ret);
    if( ret == ERROR_BUFFER_TOO_SMALL || ret == ERROR_INVALID_SIZE )
    {
        rasEntry.dwSize = rasEntrySize > sizeof(RASENTRY) ? sizeof(RASENTRY):rasEntrySize;
        rasEntrySize = rasEntry.dwSize;
    } 

    ret = RasGetEntryProperties(NULL,pszEntryName,&rasEntry,&rasEntrySize, NULL, NULL);

    //std::cout<<_T("RasGetEntryProperties, ret: ")<<ret<<"\r\n";
    printf("RasGetEntryProperties! ret=%d EntrySize=%d sizeof(RASENTRY)=%d \r\n", ret,rasEntrySize, sizeof(RASENTRY));
    return ret;
}

int ConnectVPN(const LPCTSTR pszEntryName, const LPCTSTR pszServerName, 
                const LPCTSTR pszUserName, const LPCTSTR pszPassWord)
{
    int ret = 0;

    if( CheckConnect(pszEntryName) == 0 ) return 0;

    if( GetVPN(pszEntryName) )
    {
        ret = CreateVPN(pszEntryName, pszServerName, pszUserName, pszPassWord);
        if ( ret != 0 )
        {
            return ret;
        }
    }

    HRASCONN hRasConn = NULL;
    ret = DoConnectVPN(pszEntryName, pszServerName, pszUserName, pszPassWord, &hRasConn);
    if( ret != ERROR_SUCCESS && NULL != hRasConn ){
        RasHangUp(hRasConn);
    }
    return ret;
}


int _tmain(int argc, _TCHAR* argv[])
{
    if( argc == 3 && _tcsicmp(argv[2],_T("/DELVPN")) == 0 ){    
        return DeleteVPN(argv[1]);
    }
    else if( argc == 5 ){
        return ConnectVPN(argv[1],argv[2],argv[3],argv[4]);
    }
    else{
        std::cout<<"connVPN usage:"<<"\r\n";
        std::cout<<"              EntryName ServerName UserName PassWord"<<"\r\n";
        std::cout<<"\r\n";
        std::cout<<"              EntryName /DELVPN"<<"\r\n";
        return -1;
    }
    return 0;
}

