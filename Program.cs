using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Newtonsoft.Json;
using PacketDotNet;
using SharpPcap;
using TSPacketEditor.Config;

class Program
{
    const byte XorKey = 173;
    static string baseDir = AppDomain.CurrentDomain.BaseDirectory;
    static string logFile = $"log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
    static Config mainConfig;

    static Config LoadConfig()
    {
        string json = "";
        string configDir = Path.Combine(baseDir, "Config");
        if (!Directory.Exists(configDir))
            Directory.CreateDirectory(configDir);

        string configPath = Path.Combine(configDir, "Config.json");

        if (!File.Exists(configPath))
        {
            var defaultConfig = new Config
            {
                EnableMatching = true,
                MatchCommands = new List<MatchCommand>
                {
                    new MatchCommand { Main = 0, Sub = 0 }
                }
            };

            json = JsonConvert.SerializeObject(defaultConfig, Formatting.Indented);
            File.WriteAllText(configPath, json);

            Console.WriteLine($"Config file not found. Created default config at {configPath}");
        }
        else
        {
            json = File.ReadAllText(configPath);
        }

        return JsonConvert.DeserializeObject<Config>(json)!;
    }

    static void Main(string[] args)
    {
        mainConfig = LoadConfig();
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

            // TCP
            var tcp = parsed.Extract<TcpPacket>();
            if (tcp != null && tcp.PayloadData != null && tcp.PayloadData.Length > 0)
            {
                var ip = (IPPacket)tcp.ParentPacket;

                string direction = "Unknown";
                if (processPorts.Contains(tcp.SourcePort)) direction = "Send";
                else if (processPorts.Contains(tcp.DestinationPort)) direction = "Recv";

                Console.WriteLine($"[TCP] {direction} {ip.SourceAddress}:{tcp.SourcePort} -> {ip.DestinationAddress}:{tcp.DestinationPort} Len={tcp.PayloadData.Length}");
                PrintDecodedPayload(tcp.PayloadData, direction);
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
                PrintDecodedPayload(udp.PayloadData, direction);
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
        string direction)
    {
        if (payload == null || payload.Length == 0) return;

        // XOR decode
        byte[] decodedAll = payload.Select(b => (byte)(b ^ XorKey)).ToArray();

        int offset = 0;
        int packetIndex = 0;

        while (offset + 4 <= decodedAll.Length) // ต้องมี header + length
        {
            if (decodedAll[offset] != 0xF4 || decodedAll[offset + 1] != 0x44)
            {
                offset++;
                continue;
            }

            int dataLen = BitConverter.ToUInt16(decodedAll, offset +2);

            if (offset + 4 + dataLen > decodedAll.Length)
            {
                break;
            }

            byte[] pktData = new byte[dataLen + 4];
            Array.Copy(decodedAll, offset, pktData, 0, pktData.Length);
            
            // ตรวจสอบ main/sub command
            if (dataLen >= 2)
            {
                Console.WriteLine(HexDump(pktData));

                ushort mainCmd = pktData[4];
                ushort subCmd = pktData[5];

                if (mainConfig.MatchCommands.Any(cmd => cmd.Main == mainCmd && (cmd.Sub == subCmd || cmd.Sub == 0)))
                {
                    byte[] packetBytes = new byte[4 + dataLen];
                    Array.Copy(decodedAll, offset, packetBytes, 0, 4 + dataLen);

                    string hexText = BitConverter.ToString(packetBytes).Replace("-", " ");

                    // สร้างโฟลเดอร์ Logs ถ้ายังไม่มี
                    string logDir = Path.Combine(baseDir, "Logs");
                    if (!Directory.Exists(logDir))
                        Directory.CreateDirectory(logDir);

                    string logFilePath = Path.Combine(logDir, logFile);
                    string addText = "";

                    if(mainCmd == 0x0C)
                    {
                        ushort mapId = BitConverter.ToUInt16(pktData, 17);
                        addText = "(MAP) Id=" + mapId;
                    }
                    else if (mainCmd == 0x08)
                    {
                        if (subCmd == 0x01) //gain exp ap
                        {
                            if (pktData[6] == 0x24) //exp
                            {
                                int exp = BitConverter.ToInt32(pktData, 8);
                                addText = "(GAIN EXP) " + exp;
                            }
                            else if (pktData[6] == 0x25) //ap
                            {
                                int ap = BitConverter.ToInt32(pktData, 8);
                                addText = "(GAIN AP) " + ap;
                            }
                        }
                    }
                    else if (mainCmd == 0x14)
                    {
                        if (subCmd == 0x01) // just task
                        {
                            ushort talkId = BitConverter.ToUInt16(pktData, 19);
                            addText = "(TALK) Id=" + talkId;
                            if (pktData[10] == 6 && pktData[11] == 3)
                            {
                                addText += " SELECT ANSWER";
                            }
                        }
                        else if (subCmd == 0x09) // just task
                        {
                            addText = "(SELECT ANSWER) Id=" + pktData[6];
                        }
                    }
                    else if (mainCmd == 0x18)
                    {
                        ushort taskId = BitConverter.ToUInt16(pktData, 6);
                        addText = "(TASK) Id=" + taskId;

                        if (subCmd == 0x01) //add setp
                        {
                            addText += " (ADD STEP) Step=" + pktData[8];
                        }
                        else if (subCmd == 0x02) //reduce setp
                        {
                            addText += " (REDUCE STEP) Step=" + pktData[8];
                        }
                        if (subCmd == 0x05) //add done
                        {
                            addText += " (DONE) Round=" + pktData[8];
                        }
                    }
                    else if (mainCmd == 0x33)
                    {
                        if (subCmd == 0x01) //battle
                        {
                            addText = "(BATTLE)";
                        }
                    }

                    using (var sw = new StreamWriter(logFilePath, true))
                    {
                        sw.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] ({direction}) Main={mainCmd:X2} Sub={subCmd:X2} {addText}");
                        sw.WriteLine(hexText);
                        sw.WriteLine(); // เว้นบรรทัด
                    }
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
