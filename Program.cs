using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
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

        private static IntPtr Callback;
        public static string[] LifetimeKeyNames = new string[]
        {
            "SYSTEM\\CurrentControlSet\\Control\\Notifications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\VolatileNotifications"
        };

        public static List<ulong>[] WnfStateNames = new List<ulong>[3];
        static void Main(string[] args)
        {
            var options = new CommandLineParser();
            try
            {
                options.SetTitle("WnfMonitor - Tool for monitoring Windows Notification Facility state updates");
                options.AddFlag(false, "h", "help", "Displays this help message.");
                options.AddFlag(false, "s", "sn", "Nullifies DACL for WNF StateName security descriptors");
                options.Parse(args);

                if (options.GetFlag("help"))
                {
                    options.GetHelp();
                    return;
                }

                Callback = Marshal.GetFunctionPointerForDelegate(new CallbackDelegate(NotifyCallback));
                GetAllStateNames(options);
                SubscribeToAllStateNames();
                Console.WriteLine("\n\n\nBeginning WNF Capture...\n\n\n");
                while (true)
                {

                }
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            catch (ArgumentException ex)
            {
                options.GetHelp();
                Console.WriteLine(ex.Message);
            }
        }

        private static void GetAllStateNames(CommandLineParser options)
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
                                WnfStateNames[i].Add(stateName);
                                if (options.GetFlag("sn"))
                                {
                                    bool status = ModifySecurityDescriptor(nameBuilder.ToString(), pInfoBuffer, nInfoLength, Globals.LifetimeKeyNames[i]);
                                    if (!status)
                                    {
                                        Console.WriteLine("Modify SD failed for {0}", GetWnfName(stateName));
                                    }
                                }
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
                        Callback,
                        pContextBuffer,
                        IntPtr.Zero,
                        0,
                        0);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[!] Unable to subscribe to WNF StateName: {0}\nError Code: {1:X}", GetWnfName(stateName), ntstatus);
                    }
                    else
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
            Console.WriteLine("[+] Callback function called by {0}.", GetWnfName(stateName));
            Console.WriteLine(HexDump.Dump(pBuffer, (uint)nBufferSize, 2));
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
                    wnfName = string.Format("0x{0}", stateName.ToString("X"));
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

        private static bool ModifySecurityDescriptor(string stateName, IntPtr pInfoBuffer, int nInfoLength, string registryPath)
        {
            var stateNameInt = Convert.ToUInt64(stateName, 16); 
            var wnfName = GetWnfName(stateNameInt);
            int absoluteSdSize = 1024;

            IntPtr pAbsoluteSd = Marshal.AllocHGlobal(absoluteSdSize);
            IntPtr pDacl = Marshal.AllocHGlobal(absoluteSdSize);
            IntPtr pSacl = Marshal.AllocHGlobal(absoluteSdSize);
            IntPtr pOwner = Marshal.AllocHGlobal(absoluteSdSize);
            IntPtr pPrimaryGroup = Marshal.AllocHGlobal(absoluteSdSize);
            uint lpdwAbsoluteSdSize = (uint)absoluteSdSize, DaclSize = (uint)absoluteSdSize, SaclSize = (uint)absoluteSdSize,
                OwnerSize = (uint)absoluteSdSize, PrimaryGroupSize = (uint)absoluteSdSize;

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

            IntPtr modifiedSd = Marshal.AllocHGlobal(1024);
            uint tempBufferSize = 1024;
            int modifiedSdSize = -1;

            if (status)
            {
                status = NativeMethods.SetSecurityDescriptorDacl(pAbsoluteSd, true, IntPtr.Zero, false);
                status = NativeMethods.MakeSelfRelativeSD(pAbsoluteSd, modifiedSd, ref tempBufferSize);
                if (NativeMethods.IsValidSecurityDescriptor(modifiedSd))
                {
                    modifiedSdSize = NativeMethods.GetSecurityDescriptorLength(modifiedSd);
                } else
                {
                    Console.WriteLine("Could not obtain a valid security descriptor after modification\n");
                    return false;
                }
            } 
            else
            {
                return false;
            }
            
            IntPtr phkResult;
            int ntstatus = NativeMethods.RegOpenKeyEx(
                                    Win32Consts.HKEY_LOCAL_MACHINE,
                                    registryPath,
                                    0,
                                    Win32Consts.KEY_SET_VALUE,
                                    out phkResult);

            int oldSdLength = NativeMethods.GetSecurityDescriptorLength(pInfoBuffer);
            IntPtr newInfoBuffer = Marshal.AllocHGlobal(modifiedSdSize + nInfoLength - oldSdLength);
            NativeMethods.CopyMemory(newInfoBuffer, modifiedSd, (uint)modifiedSdSize);
            NativeMethods.CopyMemory(IntPtr.Add(newInfoBuffer, modifiedSdSize), IntPtr.Add(pInfoBuffer, oldSdLength), (uint)(nInfoLength - oldSdLength));
            ntstatus = NativeMethods.RegSetValueEx(phkResult, stateName, 0, Win32Consts.REG_BINARY, newInfoBuffer, modifiedSdSize + nInfoLength - oldSdLength);

            NativeMethods.RegCloseKey(phkResult);
            Marshal.FreeHGlobal(newInfoBuffer);
            Marshal.FreeHGlobal(modifiedSd);
            Marshal.FreeHGlobal(pAbsoluteSd);
            Marshal.FreeHGlobal(pDacl);
            Marshal.FreeHGlobal(pSacl);
            Marshal.FreeHGlobal(pOwner);
            Marshal.FreeHGlobal(pPrimaryGroup);

            return ntstatus == Win32Consts.STATUS_SUCCESS;
        }

    }
}
