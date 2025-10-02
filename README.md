# TSPacketEditor

โปรแกรม **Packet Sniffer/Logger** สำหรับ Windows ที่สามารถ:

- ดักจับ TCP/UDP Packet ของโปรเซสที่เลือก
- กรองเฉพาะ Traffic ที่เกี่ยวข้องกับ Process ตาม `PID`
- ถอดรหัส Payload โดย XOR แต่ละ byte ด้วย `173`
- แยก Packet ตามโครงสร้างที่กำหนด:
  - `F4 44` : Header (2 bytes)
  - `XX XX` : ขนาดข้อมูล (2 bytes, Little Endian)
  - Payload : เนื้อหาข้อมูล ความยาวตาม size
  - ใน Payload 2 bytes แรกคือ **Main Command** และ **Sub Command**
- บันทึก Packet ที่ตรงกับ `MatchCommands` ลงไฟล์ `.txt` (บันทึกเป็น Hex string)
- รองรับการตั้งค่า Match และตัวเลือกอื่น ๆ ผ่าน `config/config.json` โดยไม่ต้อง Compile ใหม่

---

## 📦 Features
- ✅ เลือก Process ที่ต้องการติดตาม
- ✅ ดักจับได้ทั้ง TCP และ UDP
- ✅ แยกแยะทิศทาง `Send` / `Recv`
- ✅ Decode Packet ด้วย XOR Key
- ✅ แยก Packet หลายชุดที่มากับ Frame เดียว
- ✅ กำหนด Match Command หลายค่าใน `config.json`
- ✅ Log แยกไฟล์อัตโนมัติตามเวลา (`logs/log_YYYYMMDD_HHmmss.txt`)

---

## ⚙️ การตั้งค่า Config

ไฟล์ `config/config.json` จะถูกสร้างอัตโนมัติถ้าไม่พบในครั้งแรก ตัวอย่างโครงสร้าง:

```json
{
  "EnableMatch": true,
  "MatchCommands": [
    { "Main": 1, "Sub": 2 },
    { "Main": 2, "Sub": 3 },
    { "Main": 5, "Sub": 0 }
  ]
}
```

- `EnableMatch` : เปิด/ปิดการบันทึกเฉพาะ Packet ที่ตรงกับ MatchCommands
- `MatchCommands` :
  - `Main` = Main Command
  - `Sub` = Sub Command (ถ้าใส่ `0` จะจับทุกค่า Sub ของ Main นั้น)

---

## 🚀 วิธีการใช้งาน

1. ติดตั้ง [Npcap](https://nmap.org/npcap/) (จำเป็นสำหรับ SharpPcap)
2. Clone โค้ด
   ```bash
   git clone https://github.com/yourname/TSPacketEditor.git
   cd TSPacketEditor
   ```
3. Build โครงการ (เช่นใน Visual Studio)
4. Run โปรแกรม (ต้อง Run as Administrator)
5. เลือก Process ที่ต้องการดักจับ
6. โปรแกรมจะแสดงผล Packet บน Console และบันทึกลงไฟล์ในโฟลเดอร์ `logs`

---

## 📂 โครงสร้างโครงการ

```
TSPacketEditor/
│── Program.cs
│── Config/
│   └── config.json
│── Logs/
│   └── log_20251002_150000.txt
│── README.md
```

---

## 📝 License
MIT License – ใช้ได้อิสระเพื่อการศึกษาและพัฒนา

---

## 👨‍💻 Credits
พัฒนาโดย **[yourname]**

- ใช้ [SharpPcap](https://github.com/chmorgan/sharppcap) สำหรับ packet capture  
- ใช้ [Newtonsoft.Json](https://www.newtonsoft.com/json) สำหรับการอ่าน config  
