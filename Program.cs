using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using WnfMonitor.Interop;
using WnfMonitor.Library;

namespace WnfMonitor
{
    internal class Program
    {
        /*
         * Structs
         */
        private struct NotifyContext
        {
            public bool Destroyed;
            public IntPtr Event;

            public NotifyContext(bool _destroyed, IntPtr _event)
            {
                this.Destroyed = _destroyed;
                this.Event = _event;
            }
        }

        /*
         * Delegate Types
         */
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int CallbackDelegate(
            ulong StateName,
            int ChangeStamp,
            IntPtr TypeId,
            IntPtr CallbackContext,
            IntPtr Buffer,
            int BufferSize);

        public static string[] LifetimeKeyNames = new string[]
        {
            "SYSTEM\\CurrentControlSet\\Control\\Notifications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\VolatileNotifications"
        };

        public static List<ulong>[] WnfStateNames = new List<ulong>[3];
        static void Main(string[] args)
        {
            GetAllStateNames();
            SubscribeToAllStateNames();
        }

        private static void GetAllStateNames()
        {
            for (int i = 0; i < LifetimeKeyNames.Length; ++i)
            {
                WnfStateNames[i] = new List<ulong>();
                int error = NativeMethods.RegOpenKeyEx(
                        Win32Consts.HKEY_LOCAL_MACHINE,
                        Globals.LifetimeKeyNames[i],
                        0,
                        Win32Consts.KEY_READ,
                        out IntPtr phkResult);

                for (var count = 0; true; count++)
                {
                    IntPtr pInfoBuffer;
                    var nNameLength = 255;
                    var nameBuilder = new StringBuilder(nNameLength);
                    error = Win32Consts.ERROR_MORE_DATA;

                    for (var trial = 0; (error == Win32Consts.ERROR_MORE_DATA); trial++)
                    {
                        int nInfoLength = 0x1000 * trial;
                        pInfoBuffer = Marshal.AllocHGlobal(nInfoLength);
                        error = NativeMethods.RegEnumValue(
                                phkResult,
                                count,
                                nameBuilder,
                                ref nNameLength,
                                IntPtr.Zero,
                                IntPtr.Zero,
                                pInfoBuffer,
                                ref nInfoLength);

                        if (error == Win32Consts.ERROR_SUCCESS)
                        {
                            try
                            {
                                var stateName = Convert.ToUInt64(nameBuilder.ToString(), 16);
                                IntPtr pAbsoluteSd = Marshal.AllocHGlobal(1024);
                                IntPtr pDacl = Marshal.AllocHGlobal(1024);
                                IntPtr pSacl = Marshal.AllocHGlobal(1024);
                                IntPtr pOwner = Marshal.AllocHGlobal(1024);
                                IntPtr pPrimaryGroup = Marshal.AllocHGlobal(1024);
                                uint lpdwAbsoluteSdSize = 1024, DaclSize = 1024, SaclSize = 1024, OwnerSize = 1024, PrimaryGroupSize = 1024;

                                bool status = NativeMethods.MakeAbsoluteSD(
                                            pInfoBuffer, 
                                            pAbsoluteSd, 
                                            ref lpdwAbsoluteSdSize,
                                            pDacl,
                                            ref DaclSize,
                                            pSacl,
                                            ref SaclSize,
                                            pOwner,
                                            ref OwnerSize,
                                            pPrimaryGroup,
                                            ref PrimaryGroupSize);

                                status = NativeMethods.SetSecurityDescriptorDacl(pAbsoluteSd, true, IntPtr.Zero, false);

                                IntPtr modifiedSd = Marshal.AllocHGlobal(1024);
                                uint tempBufferSize = 1024;
                                int modifiedSdSize = -1;
                                status = NativeMethods.MakeSelfRelativeSD(pAbsoluteSd, modifiedSd, ref tempBufferSize);
                                if (NativeMethods.IsValidSecurityDescriptor(modifiedSd))
                                {
                                    modifiedSdSize = NativeMethods.GetSecurityDescriptorLength(modifiedSd);
                                }

                                if (!status)
                                {
                                    int errorCode = Marshal.GetLastWin32Error();
                                    Console.WriteLine("Could not modify security descriptor\nError code: " + errorCode);
                                } else
                                {
                                    ModifySecurityDescriptor(nameBuilder.ToString(), pInfoBuffer, nInfoLength, modifiedSd, modifiedSdSize);
                                }

                                WnfStateNames[i].Add(stateName);
                            }
                            catch { }
                        }

                        Marshal.FreeHGlobal(pInfoBuffer);
                    }

                    if (error != Win32Consts.ERROR_SUCCESS)
                        break;
                }

                NativeMethods.RegCloseKey(phkResult);
            }

            Console.WriteLine("[+] Added all WNF StateNames.");
        }

        private static void SubscribeToAllStateNames()
        {
            for (int i = 0; i < WnfStateNames.Length; ++i)
            {
                for (int j = 0; j < WnfStateNames[i].Count; ++j)
                {
                    IntPtr pSubscription = IntPtr.Zero;
                    IntPtr pContextBuffer = IntPtr.Zero;
                    ulong stateName = WnfStateNames[i][j];
                    int ntstatus = NativeMethods.RtlSubscribeWnfStateChangeNotification(
                        out pSubscription,
                        stateName,
                        0,
                        Marshal.GetFunctionPointerForDelegate(new CallbackDelegate(NotifyCallback)),
                        pContextBuffer,
                        IntPtr.Zero,
                        0,
                        0);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[!] Unable to subscribe to WNF StateName: {0}\nError Code: {1:X}", GetWnfName(stateName), ntstatus);
                    } else
                    {
                        Console.WriteLine("[+] Subscribed to WNF StateName: {0}", GetWnfName(stateName));
                    }

                }
            }
        }

        private static int NotifyCallback(ulong stateName,
            int nChangeStamp,
            IntPtr pTypeId,
            IntPtr pCallbackContext,
            IntPtr pBuffer,
            int nBufferSize)
        {
            Console.WriteLine("Callback function called by {0}.", GetWnfName(stateName));
            return 1;
        }

        private static string GetWnfName(ulong stateName)
        {
            string wnfName = Enum.GetName(typeof(WELL_KNOWN_WNF_NAME), stateName);
            var wnfStateName = new WNF_STATE_NAME { Data = stateName };
            var tag = BitConverter.GetBytes(wnfStateName.GetOwnerTag());

            if (string.IsNullOrEmpty(wnfName) && wnfStateName.IsValid())
            {
                if (wnfStateName.GetNameLifeTime() == WNF_STATE_NAME_LIFETIME.WellKnown)
                {
                    wnfName = string.Format("{0}.{1} 0x{2}",
                        Encoding.ASCII.GetString(tag).Trim('\0'),
                        wnfStateName.GetSequenceNumber().ToString("D3"),
                        stateName.ToString("X8"));
                }
                else
                {
                    wnfName = "N/A";
                }
            }

            return wnfName;
        }

        private static bool sdControlTest(IntPtr pInfoBuffer)
        {
            // Running control test:
            if (NativeMethods.IsValidSecurityDescriptor(pInfoBuffer))
            {
                return false;
            }

            int initialSdSize = NativeMethods.GetSecurityDescriptorLength(pInfoBuffer);
            IntPtr pControlAbsoluteSd = Marshal.AllocHGlobal(1024);
            IntPtr p1 = Marshal.AllocHGlobal(1024);
            IntPtr p2 = Marshal.AllocHGlobal(1024);
            IntPtr p3 = Marshal.AllocHGlobal(1024);
            IntPtr p4 = Marshal.AllocHGlobal(1024);
            uint controlAbsoluteSdSize = 1024, s1 = 1024, s2 = 1024, s3 = 1024, s4 = 1024;

            bool ntstatus = NativeMethods.MakeAbsoluteSD(
                        pInfoBuffer,
                        pControlAbsoluteSd,
                        ref controlAbsoluteSdSize,
                        p1,
                        ref s1,
                        p2,
                        ref s2,
                        p3,
                        ref s3,
                        p4,
                        ref s4);

            IntPtr controlSd = Marshal.AllocHGlobal(1024);
            uint bufferControlSize = 1024;
            ntstatus = NativeMethods.MakeSelfRelativeSD(pControlAbsoluteSd, controlSd, ref bufferControlSize);
            return NativeMethods.IsValidSecurityDescriptor(controlSd) && NativeMethods.GetSecurityDescriptorLength(controlSd) == initialSdSize;
        }

        private static bool ModifySecurityDescriptor(string stateName, IntPtr pInfoBuffer, int nInfoLength, IntPtr pSecurityDescriptor, int sdLength)
        {
            IntPtr phkResult;
            int status = NativeMethods.RegOpenKeyEx(
                                    Win32Consts.HKEY_LOCAL_MACHINE,
                                    "SYSTEM\\CurrentControlSet\\Control\\Notifications",
                                    0,
                                    Win32Consts.KEY_SET_VALUE,
                                    out phkResult);

            int oldSdLength = NativeMethods.GetSecurityDescriptorLength(pInfoBuffer);
            IntPtr newInfoBuffer = Marshal.AllocHGlobal(sdLength + nInfoLength - oldSdLength);
            NativeMethods.CopyMemory(newInfoBuffer, pSecurityDescriptor, (uint) sdLength);
            NativeMethods.CopyMemory(IntPtr.Add(newInfoBuffer, sdLength), IntPtr.Add(pInfoBuffer, oldSdLength), (uint) (nInfoLength - oldSdLength));
                 
            status = NativeMethods.RegSetValueEx(phkResult, stateName, 0, Win32Consts.REG_BINARY, newInfoBuffer, sdLength + nInfoLength - oldSdLength);
            return status == Win32Consts.STATUS_SUCCESS;
        }

    }
}
