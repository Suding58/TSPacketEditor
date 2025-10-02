using System.Diagnostics;
using System.Text;
using PacketDotNet;
using SharpPcap;

class Program
{
    const byte XorKey = 173;
    static string logFile = $"log_{DateTime.Now:yyyyMMdd_HHmmss}.bin";

    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("=== Diagnostic Multi-adapter Packet Sniffer (dynamic filter) ===\n");

        if (!IsAdministrator())
        {
            Console.WriteLine("Warning: Not running as Administrator. Run as admin for reliable capture.");
        }

        // 1) เลือก process แบบ interactive
        var target = SelectProcessFromList();
        if (target == null)
        {
            Console.WriteLine("No process selected. Exiting.");
            return;
        }
        Console.WriteLine($"Monitoring process: {target.ProcessName} (PID {target.Id})\n");

        // 2) เตรียม devices: เปิดทุก device ที่เปิดได้ (รวม loopback adapters)
        var devices = CaptureDeviceList.Instance;
        if (devices.Count == 0)
        {
            Console.WriteLine("No capture devices found. Install Npcap and run as Administrator.");
            return;
        }

        // เตรียม set ของ ports ที่ process ใช้
        HashSet<int> processPorts = new HashSet<int>();
        processPorts.UnionWith(TcpUdpTableHelper.GetTcpPortsByPid(target.Id));
        processPorts.UnionWith(TcpUdpTableHelper.GetUdpPortsByPid(target.Id));

        // open all devices we can and attach handlers
        var opened = new List<ICaptureDevice>();
        foreach (var dev in devices)
        {
            try
            {
                // attach handler with lambda เพื่อส่ง processPorts เข้าไป
                dev.OnPacketArrival += (sender, e) => OnPacketArrived(dev, e, target.Id, processPorts);

                dev.Open(DeviceModes.Promiscuous, 1000); // try open in promisc
                                                         // start with broad filter to ensure we see packets
                try { dev.Filter = "ip"; } catch { /* ignore if cannot set */ }

                dev.StartCapture();
                opened.Add(dev);
                //Console.WriteLine($"Opened device: {dev.Name}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to open device {dev.Name}: {ex.Message}");
            }
        }

        if (opened.Count == 0)
        {
            Console.WriteLine("No devices could be opened. Exiting.");
            return;
        }


        // 3) Background thread: every few seconds update ports for process and set BPF filter accordingly
        var stopTokenSource = new CancellationTokenSource();
        var token = stopTokenSource.Token;
        var monitorThread = new Thread(() =>
        {
            HashSet<int> lastTcp = new HashSet<int>();
            HashSet<int> lastUdp = new HashSet<int>();
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var tcp = TcpUdpTableHelper.GetTcpPortsByPid(target.Id);
                    var udp = TcpUdpTableHelper.GetUdpPortsByPid(target.Id);

                    // print changes (if any)
                    if (!SetsEqual(lastTcp, tcp) || !SetsEqual(lastUdp, udp))
                    {
                        Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] Ports for PID {target.Id}: TCP[{string.Join(",", tcp)}] UDP[{string.Join(",", udp)}]");
                        lastTcp = new HashSet<int>(tcp);
                        lastUdp = new HashSet<int>(udp);

                        // build filter string
                        var parts = new List<string>();
                        parts.AddRange(tcp.Select(p => $"tcp port {p}"));
                        parts.AddRange(udp.Select(p => $"udp port {p}"));
                        string filter = parts.Count > 0 ? string.Join(" or ", parts) : "ip"; // fallback to ip
                        Console.WriteLine($"Applying filter: {filter}");

                        // try set filter on all opened devices
                        foreach (var dev in opened)
                        {
                            try
                            {
                                dev.Filter = filter;
                            }
                            catch (Exception ex)
                            {
                                // Some adapters/drivers don't accept filter; ignore
                                Console.WriteLine($"  device {dev.Name} set filter failed: {ex.Message}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Monitor thread error: {ex.Message}");
                }

                Thread.Sleep(3000);
            }
        });
        monitorThread.IsBackground = true;
        monitorThread.Start();

        Console.WriteLine("\nCapturing... Press Ctrl+C to stop.");
        Console.CancelKeyPress += (s, e) =>
        {
            Console.WriteLine("Stopping capture...");
            e.Cancel = true;
            stopTokenSource.Cancel();

            foreach (var dev in opened)
            {
                try
                {
                    dev.StopCapture();
                    dev.Close();
                }
                catch { }
            }
            Environment.Exit(0);
        };

        // Keep main thread alive
        while (true) Thread.Sleep(1000);
    }

    static void OnPacketArrived(ICaptureDevice dev, PacketCapture e, int targetPid, HashSet<int> processPorts)
    {
        try
        {
            var raw = e.GetPacket();
            var parsed = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

            // สร้างชื่อไฟล์ log ตามเวลาปัจจุบัน

            // กำหนดคู่ Main/Sub ที่ต้องการจับหลายค่า
            var matchList = new List<(ushort Main, ushort Sub)>
            {
                (0x01, 0x02),
                (0x03, 0x04),
                (0x10, 0x20),
                (0x06, 0x00)
            };

            // TCP
            var tcp = parsed.Extract<TcpPacket>();
            if (tcp != null && tcp.PayloadData != null && tcp.PayloadData.Length > 0)
            {
                var ip = (IPPacket)tcp.ParentPacket;

                string direction = "Unknown";
                if (processPorts.Contains(tcp.SourcePort)) direction = "Send";
                else if (processPorts.Contains(tcp.DestinationPort)) direction = "Recv";

                Console.WriteLine($"[TCP] {direction} {ip.SourceAddress}:{tcp.SourcePort} -> {ip.DestinationAddress}:{tcp.DestinationPort} Len={tcp.PayloadData.Length}");
                PrintDecodedPayload(tcp.PayloadData, direction, matchList, logFile);
                return;
            }

            // UDP
            var udp = parsed.Extract<UdpPacket>();
            if (udp != null && udp.PayloadData != null && udp.PayloadData.Length > 0)
            {
                var ip = (IPPacket)udp.ParentPacket;

                string direction = "Unknown";
                if (processPorts.Contains(udp.SourcePort)) direction = "Send";
                else if (processPorts.Contains(udp.DestinationPort)) direction = "Recv";

                Console.WriteLine($"[UDP] {direction} {ip.SourceAddress}:{udp.SourcePort} -> {ip.DestinationAddress}:{udp.DestinationPort} Len={udp.PayloadData.Length}");
                PrintDecodedPayload(udp.PayloadData, direction, matchList, logFile);
                return;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Packet parse error: {ex.Message}");
        }
    }

    // replace existing PrintDecodedPayload with this version
    static void PrintDecodedPayload(
        byte[] payload,
        string direction,
        List<(ushort Main, ushort Sub)> matchCommands,
        string logFilePath)
    {
        if (payload == null || payload.Length == 0) return;

        // XOR decode
        byte[] decodedAll = payload.Select(b => (byte)(b ^ XorKey)).ToArray();

        int offset = 0;
        int packetIndex = 0;

        Console.WriteLine(HexDump(decodedAll));

        while (offset + 4 <= decodedAll.Length) // ต้องมี header + length
        {
            if (decodedAll[offset] != 0xF4 || decodedAll[offset + 1] != 0x44)
            {
                offset++;
                continue;
            }

            int dataLen = (decodedAll[offset + 2] << 8) | decodedAll[offset + 3];

            if (offset + 4 + dataLen > decodedAll.Length)
            {
                break;
            }

            byte[] pktData = new byte[dataLen];
            Array.Copy(decodedAll, offset + 4, pktData, 0, dataLen);
            
            // ตรวจสอบ main/sub command
            if (dataLen >= 2)
            {
                ushort mainCmd = pktData[0];
                ushort subCmd = pktData[1];

                if (matchCommands.Any(cmd => cmd.Main == mainCmd && ( cmd.Sub == subCmd || cmd.Sub == 0)))
                {
                    // บันทึกลงไฟล์
                    using (var fs = new FileStream(logFilePath, FileMode.Append, FileAccess.Write))
                    using (var bw = new BinaryWriter(fs))
                    {
                        bw.Write(decodedAll, offset, 4 + dataLen); // บันทึก header+length+payload
                    }

                    Console.WriteLine($"   [MATCH] Packet #{packetIndex} ({direction}) Main={mainCmd:X2} Sub={subCmd:X2} saved to {logFilePath}");
                }
            }

            offset += 4 + dataLen;
            packetIndex++;
        }
    }

    static string HexDump(byte[] bytes, int bytesPerLine = 16)
    {
        if (bytes == null) return "<null>";
        int bytesLength = bytes.Length;

        char[] HexChars = "0123456789ABCDEF".ToCharArray();

        int firstHexColumn =
              8                   // 8 characters for the address
            + 3;                  // 3 spaces

        int firstCharColumn = firstHexColumn
            + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
            + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
            + 2;                  // 2 spaces 

        int lineLength = firstCharColumn
            + bytesPerLine           // - characters to show the ascii value
            + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

        char[] line = (new System.String(' ', lineLength - 2) + Environment.NewLine).ToCharArray();
        int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
        StringBuilder result = new StringBuilder(expectedLines * lineLength);

        for (int i = 0; i < bytesLength; i += bytesPerLine)
        {
            line[0] = HexChars[(i >> 28) & 0xF];
            line[1] = HexChars[(i >> 24) & 0xF];
            line[2] = HexChars[(i >> 20) & 0xF];
            line[3] = HexChars[(i >> 16) & 0xF];
            line[4] = HexChars[(i >> 12) & 0xF];
            line[5] = HexChars[(i >> 8) & 0xF];
            line[6] = HexChars[(i >> 4) & 0xF];
            line[7] = HexChars[(i >> 0) & 0xF];

            int hexColumn = firstHexColumn;
            int charColumn = firstCharColumn;

            for (int j = 0; j < bytesPerLine; j++)
            {
                if (j > 0 && (j & 7) == 0) hexColumn++;
                if (i + j >= bytesLength)
                {
                    line[hexColumn] = ' ';
                    line[hexColumn + 1] = ' ';
                    line[charColumn] = ' ';
                }
                else
                {
                    byte b = bytes[i + j];
                    line[hexColumn] = HexChars[(b >> 4) & 0xF];
                    line[hexColumn + 1] = HexChars[b & 0xF];
                    line[charColumn] = (b < 32 ? '·' : (char)b);
                }
                hexColumn += 3;
                charColumn++;
            }
            result.Append(line);
        }
        return result.ToString();
    }




    static Process SelectProcessFromList()
    {
        Console.WriteLine("\nFetching list of running applications...");

        // ดึงโปรเซสทั้งหมดที่มี Main Window Title (เป็นวิธีง่ายๆ ในการกรองเอาเฉพาะโปรแกรมที่มี UI)
        var processes = Process.GetProcesses()
            .Where(p => !string.IsNullOrEmpty(p.MainWindowTitle))
            .OrderBy(p => p.ProcessName)
            .ToList();

        if (processes.Count == 0)
        {
            Console.WriteLine("No running applications with a user interface were found.");
            return null;
        }

        Console.WriteLine("Please select a process to monitor:");
        for (int i = 0; i < processes.Count; i++)
        {
            Console.WriteLine($"  {i}: {processes[i].ProcessName} (PID: {processes[i].Id}) - {processes[i].MainWindowTitle}");
        }

        while (true)
        {
            Console.Write("\nEnter the number of the process: ");
            string input = Console.ReadLine();
            if (int.TryParse(input, out int choice) && choice >= 0 && choice < processes.Count)
            {
                return processes[choice]; // คืนค่า Process object ที่ผู้ใช้เลือก
            }
            else
            {
                Console.WriteLine("Invalid input. Please enter a number from the list.");
            }
        }
    }

    static bool IsAdministrator()
    {
        try
        {
            var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p = new System.Security.Principal.WindowsPrincipal(id);
            return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    static bool SetsEqual(HashSet<int> a, HashSet<int> b)
    {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.SetEquals(b);
    }
}
