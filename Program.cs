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
                                // bool bDaclPresent = false;
                                // bool bDaclDefaulted = false;
                                // int sdLength = NativeMethods.GetSecurityDescriptorLength(pInfoBuffer);
                                // IntPtr pDacl = IntPtr.Zero;
                                NativeMethods.SetSecurityDescriptorDacl(pInfoBuffer, true, IntPtr.Zero, false);
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

    }
}
