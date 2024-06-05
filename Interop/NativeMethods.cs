﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WnfMonitor.Interop
{
    using NTSTATUS = Int32;
    internal class NativeMethods
    {
        /*
        * advapi32.dll
        */
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr pSecurityDescriptor,
            int RequestedStringSDRevision,
            SECURITY_INFORMATION SecurityInformation,
            out StringBuilder StringSecurityDescriptor,
            IntPtr StringSecurityDescriptorLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool IsValidSecurityDescriptor(IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] out bool lpbDaclPresent,
            out IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] out bool lpbDaclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetSecurityDescriptorDacl(
            IntPtr pSecurityDescriptor,
            [MarshalAs(UnmanagedType.Bool)] bool bDaclPresent,
            IntPtr pDacl,
            [MarshalAs(UnmanagedType.Bool)] bool bDaclDefaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegEnumValue(
            IntPtr hKey,
            int dwIndex,
            StringBuilder lpValueName,
            ref int lpcValueName,
            IntPtr lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            ref int lpcbData);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            IntPtr hKey,
            string lpSubKey,
            int ulOptions,
            int samDesired,
            out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr lpType,
            IntPtr lpData,
            ref int lpcbData);

        /*
         * ntdll.dll
         * 
         * Reference:
         *   + https://github.com/processhacker/processhacker/blob/master/phnt/include/ntexapi.h
         *
         */
        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryWnfStateData(
            in ulong StateName,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            out int ChangeStamp,
            IntPtr Buffer,
        ref uint BufferSize);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtQueryWnfStateNameInformation(
            in ulong StateName,
            WNF_STATE_NAME_INFORMATION NameInfoClass,
            IntPtr ExplicitScope,
            IntPtr InfoBuffer,
        int InfoBufferSize);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS NtUpdateWnfStateData(
            in ulong StateName,
            IntPtr Buffer,
            int Length,
            IntPtr TypeId,
            IntPtr ExplicitScope,
            int MatchingChangeScope,
            int CheckStamp);


        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlSubscribeWnfStateChangeNotification(
            out IntPtr Subscription,
            ulong StateName,
            int ChangeStamp,
            IntPtr Callback,
            IntPtr CallbackContext,
            IntPtr TypeId,
            int SerializationGroup,
            int Unknown);

        [DllImport("ntdll.dll")]
        public static extern NTSTATUS RtlUnsubscribeWnfStateChangeNotification(
            IntPtr Subscription);
    }
}
