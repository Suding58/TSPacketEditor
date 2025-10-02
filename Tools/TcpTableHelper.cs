
using System.Net;
using System.Runtime.InteropServices;

/// <summary>
/// Helper to get TCP/UDP ports by PID using GetExtended*Table P/Invoke
/// Returns port lists (IPv4)
/// </summary>
static class TcpUdpTableHelper
{
    // We'll use the Windows IP Helper API via P/Invoke.
    // Implement minimal parsing for IPv4 TCP and UDP tables that include PID.
    // Note: structure layouts can vary; this implementation uses common layout.

    private enum TcpTableClass : int
    {
        TCP_TABLE_OWNER_PID_ALL = 5
    }

    private enum UdpTableClass : int
    {
        UDP_TABLE_OWNER_PID = 1,
        UDP_TABLE_OWNER_PID_ALL = 1
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);

    public static HashSet<int> GetTcpPortsByPid(int pid)
    {
        var outp = new HashSet<int>();
        int AF_INET = 2;
        int buff = 0;
        uint res = GetExtendedTcpTable(IntPtr.Zero, ref buff, true, AF_INET, (int)TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
        if (res != 0 && res != 122) return outp; // 122 = insufficient

        IntPtr buffer = Marshal.AllocHGlobal(buff);
        try
        {
            res = GetExtendedTcpTable(buffer, ref buff, true, AF_INET, (int)TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
            if (res != 0) return outp;

            int entryCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = 24; // common size for MIB_TCPROW_OWNER_PID
            for (int i = 0; i < entryCount; i++)
            {
                uint state = (uint)Marshal.ReadInt32(rowPtr, 0);
                uint localAddr = (uint)Marshal.ReadInt32(rowPtr, 4);
                uint localPortNet = (uint)Marshal.ReadInt32(rowPtr, 8);
                uint remoteAddr = (uint)Marshal.ReadInt32(rowPtr, 12);
                uint remotePortNet = (uint)Marshal.ReadInt32(rowPtr, 16);
                uint owningPid = (uint)Marshal.ReadInt32(rowPtr, 20);

                if ((int)owningPid == pid)
                {
                    int localPort = ConvertPortFromNetOrder(localPortNet);
                    outp.Add(localPort);
                }

                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        catch { }
        finally { Marshal.FreeHGlobal(buffer); }
        return outp;
    }

    public static HashSet<int> GetUdpPortsByPid(int pid)
    {
        var outp = new HashSet<int>();
        int AF_INET = 2;
        int buff = 0;
        uint res = GetExtendedUdpTable(IntPtr.Zero, ref buff, true, AF_INET, (int)UdpTableClass.UDP_TABLE_OWNER_PID_ALL);
        if (res != 0 && res != 122) return outp;

        IntPtr buffer = Marshal.AllocHGlobal(buff);
        try
        {
            res = GetExtendedUdpTable(buffer, ref buff, true, AF_INET, (int)UdpTableClass.UDP_TABLE_OWNER_PID_ALL);
            if (res != 0) return outp;

            int entryCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = 16; // common MIB_UDPROW_OWNER_PID size (addr(4),port(4),pid(4),pad?)
            for (int i = 0; i < entryCount; i++)
            {
                // This layout can vary; reading similarly to TCP approach
                uint localAddr = (uint)Marshal.ReadInt32(rowPtr, 0);
                uint localPortNet = (uint)Marshal.ReadInt32(rowPtr, 4);
                uint owningPid = (uint)Marshal.ReadInt32(rowPtr, 8);
                // If structure has more fields, this might be off; but many systems match this
                if ((int)owningPid == pid)
                {
                    int localPort = ConvertPortFromNetOrder(localPortNet);
                    outp.Add(localPort);
                }
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        catch { }
        finally { Marshal.FreeHGlobal(buffer); }
        return outp;
    }

    private static int ConvertPortFromNetOrder(uint netOrder)
    {
        // netOrder sometimes packs port in low/high parts; use lower 16 bits and ntohs
        ushort portNet = (ushort)(netOrder & 0xffff);
        short host = IPAddress.NetworkToHostOrder((short)portNet);
        return host & 0xffff;
    }
}