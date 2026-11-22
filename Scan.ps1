[CmdletBinding()]
param(
    [string]$Username = $null,
    [string[]]$ModPath,
    [string]$OutDir = (Join-Path $env:TEMP 'CactusHacksDetector'),
    [int]$LookbackHours = 1,
    [int]$MemoryScanSeconds = 60,
    [string]$BadHashFile,
    [string]$Api,
    [switch]$NoOnline,
    [switch]$NoMemory,
    [switch]$NoUsn,
    [switch]$ModsOnly,
    [switch]$ScanVerified,
    [switch]$SkipVerified,
    [int]$VerifiedSeconds = 200,
    [switch]$JsonOnlyIfFlagged,
    [switch]$IncludeAccountProfiles,
    [switch]$Yes,
    [string]$AiApiKey = $null,
    [string]$AiModel = 'nvidia/nemotron-3-ultra-550b-a55b',
    [switch]$NoAi
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$ScriptVersion = '1.0.0'
$SelfMarker = 'CactusHacksDetector-SELF-MARKER-7f3a'

$ApiBase = 'https://nflopppowbfcutrmffhd.supabase.co/functions/v1/mcscan-api'

if ($Api) { $ApiBase = $Api } elseif ($env:MCSCAN_API) { $ApiBase = $env:MCSCAN_API }
$ApiBase = $ApiBase.TrimEnd('/')

function Test-ApiBase([string]$Value) {
    return ($Value -match '^https://') -or ($Value -match '^http://(127\.0\.0\.1|localhost)(:\d+)?$')
}

$MaxModUploadMB = 32
$MaxModUploadsPerScan = 16
$MaxModUploadBytes = 100MB

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$script:NativeSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace CactusHacksDetector
{
    public class KeyPair
    {
        public string Name; public int Key; public string Owner; public string Desc; public string Method;
    }
    public class ClassInfo
    {
        public bool Ok; public string Error; public int Major; public string ThisClass; public int BadCode;
        public string SuperClass; public int StrTotal; public int EncStr; public int DecryptRefs;
        public List<string> EncSamples = new List<string>();
        public List<string> Strings = new List<string>();
        public List<string> Caps = new List<string>();
        public List<KeyPair> Keys = new List<KeyPair>();
    }
    internal class Pool
    {
        public int[] Tag; public int[] A; public int[] C; public string[] Utf;
        public string ClassName(int idx) { return Utf[A[idx]]; }
        public void Member(int idx, out string owner, out string name, out string desc)
        {
            owner = Utf[A[A[idx]]];
            int nt = C[idx];
            name = Utf[A[nt]];
            desc = Utf[C[nt]];
        }
    }
    public static class ClassAnalyzer
    {
        private class Ev { public int Idx; public bool IsStr; public int Val; public string S; }
        private static readonly int[] OpLen = BuildLen();
        private static int[] BuildLen()
        {
            int[] l = new int[256];
            for (int i = 0; i < 256; i++) l[i] = 1;
            l[0x10] = 2; l[0x12] = 2;
            l[0x11] = 3; l[0x13] = 3; l[0x14] = 3;
            for (int i = 0x15; i <= 0x19; i++) l[i] = 2;
            for (int i = 0x36; i <= 0x3a; i++) l[i] = 2;
            l[0x84] = 3;
            for (int i = 0x99; i <= 0xa8; i++) l[i] = 3;
            l[0xa9] = 2;
            for (int i = 0xb2; i <= 0xb8; i++) l[i] = 3;
            l[0xb9] = 5; l[0xba] = 5;
            l[0xbb] = 3; l[0xbc] = 2; l[0xbd] = 3;
            l[0xc0] = 3; l[0xc1] = 3;
            l[0xc5] = 4;
            l[0xc6] = 3; l[0xc7] = 3;
            l[0xc8] = 5; l[0xc9] = 5;
            return l;
        }
        private static int U2(byte[] b, int p) { return (b[p] << 8) | b[p + 1]; }
        private static int S4(byte[] b, int p) { return (b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]; }
        public static ClassInfo Analyze(byte[] b)
        {
            ClassInfo ci = new ClassInfo();
            try
            {
                if (b == null || b.Length < 10 || S4(b, 0) != unchecked((int)0xCAFEBABE)) { ci.Error = "not a class"; return ci; }
                ci.Major = U2(b, 6);
                int n = U2(b, 8);
                Pool pool = new Pool();
                pool.Tag = new int[n]; pool.A = new int[n]; pool.C = new int[n]; pool.Utf = new string[n];
                int p = 10;
                for (int i = 1; i < n; i++)
                {
                    int t = b[p]; pool.Tag[i] = t; p++;
                    if (t == 1) { int ul = U2(b, p); p += 2; pool.Utf[i] = Encoding.UTF8.GetString(b, p, ul); p += ul; }
                    else if (t == 3 || t == 4) { pool.A[i] = S4(b, p); p += 4; }
                    else if (t == 5 || t == 6) { p += 8; i++; }
                    else if (t == 7 || t == 8 || t == 16 || t == 19 || t == 20) { pool.A[i] = U2(b, p); p += 2; }
                    else if (t == 9 || t == 10 || t == 11 || t == 12 || t == 17 || t == 18) { pool.A[i] = U2(b, p); pool.C[i] = U2(b, p + 2); p += 4; }
                    else if (t == 15) { p += 3; }
                    else { ci.Error = "bad constant pool tag " + t; return ci; }
                }
                p += 2;
                int thisIdx = U2(b, p); p += 2;
                int superIdx = U2(b, p); p += 2;
                ci.ThisClass = pool.ClassName(thisIdx);
                try { if (superIdx > 0 && superIdx < n) ci.SuperClass = pool.ClassName(superIdx); } catch (Exception) { ci.SuperClass = null; }
                int ic = U2(b, p); p += 2 + 2 * ic;
                HashSet<string> caps = new HashSet<string>();
                for (int i = 1; i < n; i++)
                {
                    int tg = pool.Tag[i];
                    if (tg == 8)
                    {
                        string sv = pool.Utf[pool.A[i]];
                        if (sv == null) sv = "";
                        if (ci.Strings.Count < 4000) ci.Strings.Add(sv);
                        ci.StrTotal++;
                        if (LooksEncrypted(sv)) { ci.EncStr++; if (ci.EncSamples.Count < 3) ci.EncSamples.Add(Printable(sv)); }
                    }
                    else if (tg == 9 || tg == 10 || tg == 11)
                    {
                        string o, nm, d;
                        pool.Member(i, out o, out nm, out d);
                        AddCaps(caps, o, nm);
                        if (tg == 10 && o == ci.ThisClass && IsDecryptDesc(d)) ci.DecryptRefs++;
                    }
                }
                ci.Caps.AddRange(caps);
                int fc = U2(b, p); p += 2;
                for (int f = 0; f < fc; f++)
                {
                    p += 6;
                    int fac = U2(b, p); p += 2;
                    for (int k = 0; k < fac; k++) { int fl = S4(b, p + 2); p += 6 + fl; }
                }
                int mc = U2(b, p); p += 2;
                for (int m = 0; m < mc; m++)
                {
                    string mname = pool.Utf[U2(b, p + 2)];
                    p += 6;
                    int mac = U2(b, p); p += 2;
                    for (int k = 0; k < mac; k++)
                    {
                        string an = pool.Utf[U2(b, p)];
                        int al = S4(b, p + 2);
                        int body = p + 6;
                        if (an == "Code") { int clen = S4(b, body + 4); ScanCode(b, body + 8, clen, pool, mname, ci); }
                        p = body + al;
                    }
                }
                ci.Ok = true;
            }
            catch (Exception ex) { ci.Error = "parse error: " + ex.Message; }
            return ci;
        }
        private static bool LooksEncrypted(string s)
        {
            if (s == null || s.Length < 6) return false;
            int odd = 0;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\t' || c == '\n' || c == '\r') continue;
                if (char.IsControl(c) || c == (char)0xFFFD || (c >= (char)0xE000 && c <= (char)0xF8FF)) odd++;
            }
            return odd * 4 >= s.Length;
        }
        private static string Printable(string s)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.Length && i < 24; i++)
            {
                char c = s[i];
                if (c >= 32 && c < 127) sb.Append(c); else sb.Append("\\u").Append(((int)c).ToString("x4"));
            }
            return sb.ToString();
        }
        private static bool IsDecryptDesc(string d)
        {
            return d == "(Ljava/lang/String;)Ljava/lang/String;" || d == "(II)Ljava/lang/String;" || d == "(I)Ljava/lang/String;" || d == "([B)Ljava/lang/String;"
                || d == "([C)Ljava/lang/String;" || d == "(Ljava/lang/String;I)Ljava/lang/String;" || d == "(J)Ljava/lang/String;" || d == "(IJ)Ljava/lang/String;";
        }
        private static void AddCaps(HashSet<string> caps, string o, string nm)
        {
            if (o == "java/lang/Runtime" && nm == "exec") caps.Add("exec");
            if (o == "java/lang/ProcessBuilder" && (nm == "start" || nm == "<init>")) caps.Add("exec");
            if (nm == "defineClass" || nm == "defineAnonymousClass") caps.Add("classdef");
            if (o == "java/net/URLClassLoader") caps.Add("classdef");
            if (o == "java/lang/reflect/Method" && nm == "invoke") caps.Add("reflect");
            if (o == "java/lang/Class" && nm == "forName") caps.Add("reflect");
            if (o == "java/awt/Robot")
            {
                if (nm == "mousePress" || nm == "mouseRelease") caps.Add("robot-mouse");
                if (nm == "keyPress" || nm == "keyRelease") caps.Add("robot-key");
                if (nm == "createScreenCapture") caps.Add("robot-screen");
            }
            if (o == "java/lang/System" && (nm == "load" || nm == "loadLibrary")) caps.Add("native-load");
            if (o.StartsWith("com/sun/jna")) caps.Add("jna");
            if (o.StartsWith("java/net/Socket") || (o.StartsWith("java/net/URL") && o != "java/net/URLClassLoader") || o.StartsWith("java/net/HttpURLConnection")
                || o.StartsWith("java/net/http/HttpClient") || o.StartsWith("javax/net/ssl")) caps.Add("net");
            if (o == "java/net/ServerSocket") caps.Add("listen");
            if (o == "sun/misc/Unsafe" || o == "jdk/internal/misc/Unsafe") caps.Add("unsafe");
            if (o == "java/util/Base64$Decoder") caps.Add("b64");
            if (o == "javax/crypto/Cipher") caps.Add("cipher");
            if (o == "java/util/zip/GZIPInputStream" || o == "java/util/zip/InflaterInputStream") caps.Add("inflate");
            if (o.StartsWith("org/lwjgl/glfw/GLFW") && nm.StartsWith("glfwSet") && nm.EndsWith("Callback")) caps.Add("glfw-callback");
            if (o.StartsWith("com/github/kwhat/jnativehook") || o.StartsWith("org/jnativehook")) caps.Add("jnativehook");
            if (nm == "attackEntity") caps.Add("attack");
            if (o.StartsWith("org/lwjgl/input/Keyboard")) caps.Add("lwjgl2");
            if (o.StartsWith("org/lwjgl/glfw/GLFW") || o.StartsWith("com/mojang/blaze3d/platform/InputConstants")
                || o.StartsWith("net/minecraft/client/util/InputUtil")) caps.Add("glfw");
            if (nm == "getResourceAsStream" && (o == "java/lang/Class" || o == "java/lang/ClassLoader")) caps.Add("resource-read");
            if (nm == "defineHiddenClass") caps.Add("classdef");
            if (o.StartsWith("com/sun/tools/attach")) caps.Add("attach");
            if (o.StartsWith("java/lang/instrument")) caps.Add("instrument");
            if (o == "org/spongepowered/asm/mixin/Mixins" && nm == "addConfiguration") caps.Add("mixin-dyn");
        }
        private static List<Ev> Trim(List<Ev> ev, int idx)
        {
            List<Ev> r = new List<Ev>();
            foreach (Ev e in ev) { if (idx - e.Idx <= 12) r.Add(e); }
            if (r.Count > 64) r = r.GetRange(r.Count - 32, 32);
            return r;
        }
        private static void DetectKey(List<Ev> ev, int idx, string owner, string desc, string mname, ClassInfo ci)
        {
            if (ci.Keys.Count >= 200 || ev.Count == 0 || desc == null) return;
            bool hasI = false; bool hasS = false;
            int i = desc.IndexOf('(') + 1;
            int end = desc.IndexOf(')');
            while (i > 0 && i < end)
            {
                char ch = desc[i];
                if (ch == 'L')
                {
                    int j = desc.IndexOf(';', i);
                    if (desc.Substring(i, j - i + 1) == "Ljava/lang/String;") hasS = true;
                    i = j + 1;
                }
                else if (ch == '[')
                {
                    while (desc[i] == '[') i++;
                    if (desc[i] == 'L') i = desc.IndexOf(';', i) + 1; else i++;
                }
                else { if (ch == 'I' || ch == 'C') hasI = true; i++; }
            }
            if (!hasI || !hasS) return;
            Ev s = null;
            foreach (Ev e in ev) { if (idx - e.Idx <= 10 && e.IsStr) { s = e; break; } }
            if (s == null) return;
            foreach (Ev e2 in ev)
            {
                if (idx - e2.Idx <= 10 && !e2.IsStr && e2.Idx > s.Idx && e2.Val >= 8 && e2.Val <= 400)
                {
                    KeyPair kp = new KeyPair();
                    kp.Name = s.S; kp.Key = e2.Val; kp.Owner = owner; kp.Desc = desc; kp.Method = mname;
                    ci.Keys.Add(kp);
                    return;
                }
            }
        }
        private static void ScanCode(byte[] b, int start, int clen, Pool pool, string mname, ClassInfo ci)
        {
            int pc = 0; int idx = 0;
            List<Ev> ev = new List<Ev>();
            while (pc < clen)
            {
                int op = b[start + pc];
                int ln = OpLen[op];
                if (op == 0xaa)
                {
                    int q = (pc + 1 + 3) & ~3;
                    int lo = S4(b, start + q + 4); int hi = S4(b, start + q + 8);
                    ln = (q - pc) + 12 + (hi - lo + 1) * 4;
                }
                else if (op == 0xab)
                {
                    int q2 = (pc + 1 + 3) & ~3;
                    int npairs = S4(b, start + q2 + 4);
                    ln = (q2 - pc) + 8 + npairs * 8;
                }
                else if (op == 0xc4) { ln = (b[start + pc + 1] == 0x84) ? 6 : 4; }
                if (ln <= 0 || pc + ln > clen) { ci.BadCode++; return; }
                if (op >= 0x02 && op <= 0x08) { Ev e = new Ev(); e.Idx = idx; e.IsStr = false; e.Val = op - 3; ev.Add(e); }
                else if (op == 0x10) { Ev e = new Ev(); e.Idx = idx; e.IsStr = false; e.Val = unchecked((sbyte)b[start + pc + 1]); ev.Add(e); }
                else if (op == 0x11) { Ev e = new Ev(); e.Idx = idx; e.IsStr = false; e.Val = unchecked((short)U2(b, start + pc + 1)); ev.Add(e); }
                else if (op == 0x12 || op == 0x13)
                {
                    int cix = (op == 0x12) ? b[start + pc + 1] : U2(b, start + pc + 1);
                    if (cix > 0 && cix < pool.Tag.Length)
                    {
                        if (pool.Tag[cix] == 8) { Ev e = new Ev(); e.Idx = idx; e.IsStr = true; e.S = pool.Utf[pool.A[cix]]; ev.Add(e); }
                        else if (pool.Tag[cix] == 3) { Ev e = new Ev(); e.Idx = idx; e.IsStr = false; e.Val = pool.A[cix]; ev.Add(e); }
                    }
                }
                else if (op >= 0xb6 && op <= 0xba)
                {
                    if (op != 0xba)
                    {
                        int mi = U2(b, start + pc + 1);
                        string o, nm, d;
                        pool.Member(mi, out o, out nm, out d);
                        DetectKey(ev, idx, o, d, mname, ci);
                    }
                    ev = Trim(ev, idx);
                }
                pc += ln;
                idx++;
                if (ev.Count > 64) ev = ev.GetRange(ev.Count - 32, 32);
            }
            if (pc != clen) ci.BadCode++;
        }
    }
    public static class Util
    {
        public static double Entropy(byte[] b)
        {
            if (b == null || b.Length == 0) return 0;
            int[] cnt = new int[256];
            for (int i = 0; i < b.Length; i++) cnt[b[i]]++;
            double h = 0; double n = b.Length;
            for (int j = 0; j < 256; j++)
            {
                if (cnt[j] == 0) continue;
                double p = cnt[j] / n;
                h -= p * Math.Log(p, 2);
            }
            return h;
        }
    }
    public class MemResult
    {
        public bool Ok; public string Error; public long BytesScanned; public int Regions; public bool TimedOut;
        public Dictionary<string, int> Hits = new Dictionary<string, int>();
    }
    public static class MemScan
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct MBI
        {
            public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
            public IntPtr RegionSize; public uint State; public uint Protect; public uint Type;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UIntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, UIntPtr len);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, UIntPtr size, out UIntPtr read);
        private static void SearchBuf(byte[] buf, int have, int startLimit, byte[][] pats, int[] head, int[] nxt, byte[] lo, Dictionary<string, int> hits, string[] terms)
        {
            int limit = Math.Min(startLimit, have - 1);
            for (int i = 0; i < limit; i++)
            {
                int key = (lo[buf[i]] << 8) | lo[buf[i + 1]];
                int pi = head[key];
                while (pi >= 0)
                {
                    byte[] pt = pats[pi];
                    if (i + pt.Length <= have)
                    {
                        int j = 2;
                        while (j < pt.Length && lo[buf[i + j]] == pt[j]) j++;
                        if (j == pt.Length)
                        {
                            int c;
                            hits.TryGetValue(terms[pi], out c);
                            hits[terms[pi]] = c + 1;
                        }
                    }
                    pi = nxt[pi];
                }
            }
        }
        public static MemResult Scan(int pid, string[] terms, int maxSeconds, long maxBytes)
        {
            MemResult r = new MemResult();
            IntPtr h = IntPtr.Zero;
            try
            {
                if (IntPtr.Size != 8) { r.Error = "needs 64-bit PowerShell"; return r; }
                int n = terms.Length;
                byte[][] pats = new byte[n][];
                int maxLen = 0;
                byte[] lo = new byte[256];
                for (int i = 0; i < 256; i++) lo[i] = (byte)((i >= 65 && i <= 90) ? i + 32 : i);
                int[] head = new int[65536];
                for (int i = 0; i < head.Length; i++) head[i] = -1;
                int[] nxt = new int[n];
                for (int i = 0; i < n; i++)
                {
                    pats[i] = Encoding.ASCII.GetBytes(terms[i].ToLowerInvariant());
                    if (pats[i].Length < 4) continue;
                    if (pats[i].Length > maxLen) maxLen = pats[i].Length;
                    int key = (pats[i][0] << 8) | pats[i][1];
                    nxt[i] = head[key]; head[key] = i;
                }
                if (maxLen == 0) { r.Error = "no usable terms"; return r; }
                h = OpenProcess(0x0410, false, pid);
                if (h == IntPtr.Zero) { r.Error = "cannot open process (try running as Administrator)"; return r; }
                DateTime deadline = DateTime.UtcNow.AddSeconds(maxSeconds);
                int overlap = maxLen - 1; int chunk = 1 << 20;
                byte[] buf = new byte[chunk + overlap];
                long addr = 0; long maxAddr = 0x7FFFFFFFFFFF;
                UIntPtr mbiSize = new UIntPtr((uint)Marshal.SizeOf(typeof(MBI)));
                while (addr < maxAddr)
                {
                    MBI mbi;
                    UIntPtr got = VirtualQueryEx(h, new IntPtr(addr), out mbi, mbiSize);
                    if (got == UIntPtr.Zero) break;
                    long rsize = mbi.RegionSize.ToInt64();
                    long rbase = mbi.BaseAddress.ToInt64();
                    if (rsize <= 0) break;
                    bool readable = mbi.State == 0x1000 && mbi.Type == 0x20000 && (mbi.Protect & 0x100) == 0
                                    && (mbi.Protect & 0x01) == 0 && mbi.Protect != 0;
                    if (readable)
                    {
                        r.Regions++;
                        long off = 0;
                        while (off < rsize)
                        {
                            if (DateTime.UtcNow > deadline || r.BytesScanned > maxBytes) { r.TimedOut = true; break; }
                            long remain = rsize - off;
                            int effective = (int)Math.Min((long)chunk, remain);
                            int toRead = (int)Math.Min((long)(effective + overlap), remain);
                            UIntPtr rd;
                            bool okRead = ReadProcessMemory(h, new IntPtr(rbase + off), buf, new UIntPtr((uint)toRead), out rd);
                            int have = (int)rd.ToUInt32();
                            if (okRead || have > 0) SearchBuf(buf, have, Math.Min(effective, have), pats, head, nxt, lo, r.Hits, terms);
                            r.BytesScanned += effective;
                            off += effective;
                        }
                        if (r.TimedOut) break;
                    }
                    addr = rbase + rsize;
                }
                r.Ok = true;
            }
            catch (Exception ex) { r.Error = ex.Message; }
            finally { if (h != IntPtr.Zero) CloseHandle(h); }
            return r;
        }
    }
}
'@

$script:Native = $false
$script:NativeError = $null
try {
    if (-not ('CactusHacksDetector.ClassAnalyzer' -as [type])) { Add-Type -TypeDefinition $script:NativeSource -Language CSharp -ErrorAction Stop }
    $script:Native = $true
} catch { $script:NativeError = $_.Exception.Message }

$script:ProfilerSource = @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
namespace CactusHacksDetector
{
    public class ProfileBuilder
    {
        private class Rec { public string Name; public string Super; public bool Mixin; public int Score; }
        private class Parsed
        {
            public string This; public string Super; public bool IsMixin;
            public List<string> Fields = new List<string>();
            public List<string> Methods = new List<string>();
            public List<string> Strings = new List<string>();
            public List<string> MixinTargets = new List<string>();
            public List<string> Injects = new List<string>();
            public List<string> Refs = new List<string>();
            public HashSet<string> Flags = new HashSet<string>();
        }
        private class Slot { public string Name; public HashSet<string> Flags; public string[] Refs; public bool Pvp; public bool Click; }
        private class Pool
        {
            public int[] Tag; public int[] A; public int[] C; public string[] Utf;
            public string ClassName(int i) { if (i <= 0 || i >= Utf.Length) return ""; int u = A[i]; return (u > 0 && u < Utf.Length && Utf[u] != null) ? Utf[u] : ""; }
            public string Str(int i) { return (i > 0 && i < Utf.Length && Utf[i] != null) ? Utf[i] : ""; }
        }
        private readonly List<Rec> recs = new List<Rec>();
        private readonly Dictionary<string, int> pkgs = new Dictionary<string, int>();
        private readonly Dictionary<string, int> methods = new Dictionary<string, int>();
        private readonly Dictionary<string, int> fields = new Dictionary<string, int>();
        private readonly Dictionary<string, int> strs = new Dictionary<string, int>();
        private readonly Dictionary<string, int> mixins = new Dictionary<string, int>();
        private readonly Dictionary<string, int> targets = new Dictionary<string, int>();
        private readonly Dictionary<string, int> api = new Dictionary<string, int>();
        private readonly HashSet<string> vocab = new HashSet<string>();
        private readonly HashSet<string> mixinMethods = new HashSet<string>();
        private readonly List<string> mapped = new List<string>();
        private readonly Dictionary<string, int> capScore = new Dictionary<string, int>();
        private readonly Dictionary<string, string> capText = new Dictionary<string, string>();
        private readonly Dictionary<string, string[]> behaviors = new Dictionary<string, string[]>();
        private readonly List<Slot> slots = new List<Slot>();
        private readonly Dictionary<string, int> refCount = new Dictionary<string, int>();
        private readonly Dictionary<string, int> famCount = new Dictionary<string, int>();
        private readonly Dictionary<string, int> famStrong = new Dictionary<string, int>();
        private readonly Dictionary<string, List<string>> famEx = new Dictionary<string, List<string>>();
        private readonly HashSet<string> ownNames = new HashSet<string>();
        private readonly List<string> mixinNames = new List<string>();
        private static readonly string[] ActionFlags = new string[] { "attackEntity", "interactEntity", "setRotation", "movePacket", "interactPacket", "clickSlot", "clickPacket", "swapSlot", "setVelocity", "setOnGround", "swingPacket", "actionPacket", "setSprinting", "robot", "nativeHook", "depthOff", "offhandSwap", "stepHeight" };
        private int total; private int shortNames; private int junkNames; private int enc; private int mappedCount; private int failed;

        private static readonly string[] VocabSub = new string[] {
            "killaura", "crystalaura", "autocrystal", "triggerbot", "aimassist", "aimbot", "silentaim", "autoclicker", "jitterclick",
            "autototem", "autopearl", "autoanchor", "anchoraura", "anchormacro", "bedaura", "autodtap", "doubleanchor", "hitboxexpand",
            "reachhack", "velocityhack", "noknockback", "antiknockback", "antikb", "nofall", "speedhack", "flyhack", "bunnyhop", "bhop",
            "scaffold", "fastplace", "fastbreak", "autosprint", "sprintreset", "autoblock", "clickaura", "multiaura", "attackaura",
            "playeresp", "chestesp", "storageesp", "blockesp", "xrayhack", "autominer", "airjump", "longjump", "waterwalk", "noslow",
            "antiweb", "timerhack", "pingspoof", "packetspoof", "fakelag", "lagswitch", "hitselect", "stunslam", "maceswap", "breachswap",
            "autobreach", "autohitcrystal", "inventorytotem", "hovertotem", "autodoublehand", "keypearl", "autotpa", "webmacro",
            "autofirework", "elytraswap", "shielddisabler", "shieldbreaker", "axespam", "antibot", "rotationspoof",
            "silentrotation", "cpsbypass", "antimissclick", "tpaura", "nojumpdelay", "inventorystealer", "invcleaner", "maceaura",
            "autoarmor", "autopot", "lagreach", "popswitch", "legitcrystal", "legitanchor", "legittotem",
            "autocrit", "autoweapon", "silentswap", "packetfly", "elytrafly", "boatfly", "safewalk", "holefiller", "selftrap",
            "autotrap", "autoweb", "autooffhand", "offhandcrystal", "backtrack", "hitboxexpander", "velocitycancel", "fastbow",
            "autobow", "bowaimbot", "speedmine", "packetmine", "autosurround", "norotate"
        };
        private static readonly string[] VocabTok = new string[] { "esp", "aura", "xray", "bhop", "tracers", "nuker", "jesus" };
        private static readonly string[] StrongFlags = new string[] { "attackEntity", "interactEntity", "atan2", "setRotation", "movePacket", "interactPacket", "clickSlot", "clickPacket", "robot", "nativeHook", "glfwInput", "depthOff", "reachDistance", "swapSlot", "setVelocity", "setOnGround", "reflectInvoke", "setAccessible", "raycast", "entityQuery", "setSprinting", "swingPacket", "actionPacket", "commandPacket" };
        private static readonly string[][] MixinRules = new string[][] {
            new string[] { "(?i)(getTargetingMargin|method_5871)", "Hooks the entity targeting margin with a mixin (hitbox expansion behaviour)", "attackEntity,crosshair,entityHitResult,entityQuery" },
            new string[] { "(?i)(sendImmediately|sendInternal|channelRead0)", "Hooks the packet send and receive path with a mixin (blink / fake lag / packet cancel behaviour)", "movePacket,interactPacket,swingPacket;timing,random,setKeyPressed" },
            new string[] { "(?i)(shouldSlowDown|method_6115)", "Hooks the item-use slowdown with a mixin (no slow behaviour)", "movePacket,setVelocity;setSprinting" },
            new string[] { "(?i)(handleAttack|doAttack|method_1536)", "Hooks the attack action with a mixin (auto attack / criticals / combo behaviour)", "attackEntity;crosshair,entityHitResult,random;timing,random,attackCooldown" },
            new string[] { "(?i)(sendMovementPackets|method_3136|updateWalkingPlayer)", "Hooks the movement-packet send with a mixin while computing rotations (silent aim / rotation spoof behaviour)", "atan2;setRotation,movePacket" }
        };
        private static readonly Dictionary<string, string> Inter = BuildInter();
        private static Dictionary<string, string> BuildInter()
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            string[] rows = new string[] {
                "attackEntity=method_2918,method_34206,m_105223_",
                "interactEntity=method_2905,method_2917,method_34207,method_34208",
                "clickSlot=method_2906",
                "useItem=method_2919,method_2896",
                "swapSlot=method_2911",
                "reachDistance=method_2904,method_55754,method_55755,method_3190",
                "setPos=method_5814,method_33574,m_6034_",
                "setOnGround=method_24830,m_6853_",
                "setVelocity=method_5762,method_18799,method_18800,m_20256_,m_20334_",
                "setRotation=method_36456,method_36457,method_5847,m_146922_,m_146926_",
                "setSprinting=method_5728,m_6858_",
                "eyePos=method_33571,method_5836,m_20299_",
                "lookVec=method_5828,method_5720,m_20252_",
                "boundingBox=method_5829,m_20191_",
                "raycast=method_5745,method_17742",
                "entityQuery=method_8390,method_8333,method_8335,method_18023,method_18467,m_6443_,m_6249_",
                "sendPacket=method_52787,method_2883,method_10743",
                "swing=method_6104,method_23667,m_6674_",
                "attackCooldown=method_7261,m_36403_",
                "distCheck=method_5739,method_5858,method_5707,m_20270_,m_20280_"
            };
            for (int i = 0; i < rows.Length; i++)
            {
                int eq = rows[i].IndexOf('=');
                string flag = rows[i].Substring(0, eq);
                string[] ids = rows[i].Substring(eq + 1).Split(',');
                for (int k = 0; k < ids.Length; k++) d[ids[k]] = flag;
            }
            return d;
        }
        private static bool HasId(string c, string id)
        {
            int i = c.IndexOf(id, StringComparison.Ordinal);
            while (i >= 0)
            {
                int e = i + id.Length;
                if (e >= c.Length || c[e] < '0' || c[e] > '9') return true;
                i = c.IndexOf(id, e, StringComparison.Ordinal);
            }
            return false;
        }
        private static bool IsEntityDesc(string t) { return t.EndsWith("/Entity;", StringComparison.Ordinal) || t.EndsWith("/class_1297;", StringComparison.Ordinal); }
        private static bool IsPlayerDesc(string t) { return t.EndsWith("/Player;", StringComparison.Ordinal) || t.EndsWith("/PlayerEntity;", StringComparison.Ordinal) || t.EndsWith("/class_1657;", StringComparison.Ordinal) || t.EndsWith("/class_746;", StringComparison.Ordinal) || t.EndsWith("/LocalPlayer;", StringComparison.Ordinal); }
        private static void NoteDesc(string o, string n, string d, HashSet<string> fl)
        {
            if (d == null || d.Length < 3 || d[0] != '(') return;
            int close = d.IndexOf(')');
            if (close < 0) return;
            string args = d.Substring(1, close - 1);
            string ret = d.Substring(close + 1);
            bool mgr = o.EndsWith("MultiPlayerGameMode", StringComparison.Ordinal) || o.EndsWith("ClientPlayerInteractionManager", StringComparison.Ordinal) || HasId(o, "class_636");
            if (mgr && ret == "V" && args.Length > 4)
            {
                string[] parts = args.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && IsPlayerDesc(parts[0] + ";") && IsEntityDesc(parts[1] + ";")) fl.Add("attackEntity");
            }
            if (mgr && args.StartsWith("III", StringComparison.Ordinal) && ret == "V") fl.Add("clickSlot");
            bool conn = o.EndsWith("ClientPacketListener", StringComparison.Ordinal) || o.EndsWith("ClientPlayNetworkHandler", StringComparison.Ordinal) || o.EndsWith("ClientCommonNetworkHandler", StringComparison.Ordinal)
                || o.EndsWith("ClientConnection", StringComparison.Ordinal) || o.EndsWith("/Connection", StringComparison.Ordinal) || HasId(o, "class_634") || HasId(o, "class_8673") || HasId(o, "class_2535");
            if (conn && ret == "V" && (args == "Lnet/minecraft/network/protocol/Packet;" || args == "Lnet/minecraft/network/packet/Packet;" || args == "Lnet/minecraft/class_2596;")) fl.Add("sendPacket");
            if (ret.Length > 4 && args.Length > 0 && (args.IndexOf("ClipContext;", StringComparison.Ordinal) >= 0 || args.IndexOf("RaycastContext;", StringComparison.Ordinal) >= 0 || args.IndexOf("class_3959;", StringComparison.Ordinal) >= 0)) fl.Add("raycast");
            if (args == "DFZ" && ret.EndsWith("HitResult;", StringComparison.Ordinal)) fl.Add("raycast");
            if (ret == "Ljava/util/List;" && (args.IndexOf("/AABB;", StringComparison.Ordinal) >= 0 || args.IndexOf("/Box;", StringComparison.Ordinal) >= 0 || args.IndexOf("/class_238;", StringComparison.Ordinal) >= 0)
                && (args.IndexOf("Ljava/lang/Class;", StringComparison.Ordinal) >= 0 || args.IndexOf("/Entity;", StringComparison.Ordinal) >= 0 || args.IndexOf("/class_1297;", StringComparison.Ordinal) >= 0 || args.IndexOf("TypeFilter;", StringComparison.Ordinal) >= 0 || args.IndexOf("EntityTypeTest;", StringComparison.Ordinal) >= 0 || args.IndexOf("class_5575;", StringComparison.Ordinal) >= 0)) fl.Add("entityQuery");
        }
        private static bool External(string c)
        {
            return c.StartsWith("java/", StringComparison.Ordinal) || c.StartsWith("javax/", StringComparison.Ordinal) || c.StartsWith("net/minecraft/", StringComparison.Ordinal)
                || c.StartsWith("com/mojang/", StringComparison.Ordinal) || c.StartsWith("org/lwjgl/", StringComparison.Ordinal) || c.StartsWith("org/spongepowered/", StringComparison.Ordinal)
                || c.StartsWith("net/fabricmc/", StringComparison.Ordinal) || c.StartsWith("net/minecraftforge/", StringComparison.Ordinal) || c.StartsWith("net/neoforged/", StringComparison.Ordinal)
                || c.StartsWith("com/google/", StringComparison.Ordinal) || c.StartsWith("org/apache/", StringComparison.Ordinal) || c.StartsWith("it/unimi/", StringComparison.Ordinal)
                || c.StartsWith("kotlin/", StringComparison.Ordinal) || c.StartsWith("org/joml/", StringComparison.Ordinal) || c.StartsWith("io/netty/", StringComparison.Ordinal)
                || c.StartsWith("org/slf4j/", StringComparison.Ordinal) || c.StartsWith("org/objectweb/", StringComparison.Ordinal);
        }
        private static void NoteField(string o, string n, HashSet<string> fl)
        {
            if (n == "SWAP_ITEM_WITH_OFFHAND" || n == "SWAP_HELD_ITEMS") { fl.Add("offhandSwap"); return; }
            if (n == "stepHeight" || n == "maxUpStep" || n == "field_5013" || n == "f_19793_" || n == "STEP_HEIGHT" || n == "GENERIC_STEP_HEIGHT") { fl.Add("stepHeight"); return; }
            bool client = o.EndsWith("/MinecraftClient", StringComparison.Ordinal) || o.EndsWith("/Minecraft", StringComparison.Ordinal) || HasId(o, "class_310");
            if (client && (n == "crosshairTarget" || n == "hitResult" || n == "field_1765" || n == "f_91077_" || n == "crosshairPickEntity" || n == "targetedEntity" || n == "field_1692" || n == "f_91076_")) { fl.Add("crosshair"); return; }
            bool inv = o.EndsWith("/PlayerInventory", StringComparison.Ordinal) || o.EndsWith("/Inventory", StringComparison.Ordinal) || HasId(o, "class_1661");
            if (inv && (n == "selectedSlot" || n == "selected" || n == "field_7545" || n == "f_35977_")) fl.Add("slotField");
        }
        private static readonly string[] PvpHints = new string[] { "totem", "pearl", "anchor", "crystal", "glowstone", "mace" };

        private static string Squash(string s)
        {
            StringBuilder sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c >= 'A' && c <= 'Z') sb.Append((char)(c + 32));
                else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) sb.Append(c);
            }
            return sb.ToString();
        }
        private static List<string> Tokens(string s)
        {
            List<string> r = new List<string>();
            StringBuilder cur = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bool up = c >= 'A' && c <= 'Z'; bool lo = c >= 'a' && c <= 'z'; bool dg = c >= '0' && c <= '9';
                if (!up && !lo && !dg)
                {
                    if (cur.Length > 0) { r.Add(cur.ToString().ToLowerInvariant()); cur.Length = 0; }
                    continue;
                }
                if (cur.Length > 0)
                {
                    char last = cur[cur.Length - 1];
                    if (up && last >= 'a' && last <= 'z') { r.Add(cur.ToString().ToLowerInvariant()); cur.Length = 0; }
                    else if (lo && cur.Length >= 2 && last >= 'A' && last <= 'Z' && cur[cur.Length - 2] >= 'A' && cur[cur.Length - 2] <= 'Z')
                    {
                        r.Add(cur.ToString(0, cur.Length - 1).ToLowerInvariant());
                        cur.Remove(0, cur.Length - 1);
                    }
                }
                cur.Append(c);
            }
            if (cur.Length > 0) r.Add(cur.ToString().ToLowerInvariant());
            return r;
        }
        private int Vocab(string text, HashSet<string> found)
        {
            if (text == null || text.Length < 3) return 0;
            if (text.Length > 120) text = text.Substring(text.Length - 120);
            int before = found.Count;
            string sq = Squash(text);
            int cut = Math.Max(text.LastIndexOf('/'), text.LastIndexOf('.'));
            string lastSeg = Squash(cut >= 0 ? text.Substring(cut + 1) : text);
            if (lastSeg == "wtap" || lastSeg == "wtapmodule") found.Add("wtap");
            if (sq.Length >= 4)
            {
                for (int i = 0; i < VocabSub.Length; i++)
                {
                    string t = VocabSub[i];
                    int ix = sq.IndexOf(t, StringComparison.Ordinal);
                    if (ix < 0) continue;
                    string rest = sq.Substring(ix + t.Length);
                    if (t == "scaffold" && rest.StartsWith("ing", StringComparison.Ordinal)) continue;
                    if (t == "nofall" && rest.StartsWith("back", StringComparison.Ordinal)) continue;
                    if (t == "noslow" && rest.StartsWith("er", StringComparison.Ordinal)) continue;
                    found.Add(t);
                }
            }
            List<string> tk = Tokens(text);
            for (int a = 0; a < tk.Count; a++)
            {
                for (int b = 0; b < VocabTok.Length; b++) { if (tk[a] == VocabTok[b]) found.Add(VocabTok[b]); }
            }
            return found.Count - before;
        }
        private static bool IsMapped(string s)
        {
            int n = s.Length;
            if (n < 7 || n > 60) return false;
            if (s.IndexOf("net/minecraft/class_", StringComparison.Ordinal) >= 0 || s.IndexOf("net.minecraft.class_", StringComparison.Ordinal) >= 0) return true;
            int us = s.IndexOf('_');
            if (us < 0) return false;
            string head = s.Substring(0, us);
            if (head == "field" || head == "method" || head == "class")
            {
                int i = us + 1;
                int d = 0;
                while (i < n && s[i] >= '0' && s[i] <= '9') { i++; d++; }
                return d >= 3 && (i == n || s[i] == '_');
            }
            if ((head == "f" || head == "m") && s[n - 1] == '_')
            {
                int d2 = 0;
                for (int i2 = us + 1; i2 < n - 1; i2++) { if (s[i2] >= '0' && s[i2] <= '9') d2++; else return false; }
                return d2 >= 3;
            }
            return false;
        }
        private static bool Junk(string leaf)
        {
            if (leaf.Length < 3) return false;
            for (int i = 0; i < leaf.Length; i++) { char c = leaf[i]; if (c != 'I' && c != 'l' && c != '1' && c != 'O' && c != '0' && c != '_') return false; }
            return true;
        }
        private static int U2(byte[] b, int p) { return (b[p] << 8) | b[p + 1]; }
        private static int S4(byte[] b, int p) { return (b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]; }

        private static string Simple(string path)
        {
            if (path == null) return "";
            int i = path.LastIndexOf('/');
            string s = i >= 0 ? path.Substring(i + 1) : path;
            int d = s.LastIndexOf('.');
            return d > 0 && d < s.Length - 1 && path.IndexOf('/') < 0 ? s.Substring(d + 1) : s;
        }
        private static string DescToClass(string d)
        {
            if (d == null) return "";
            if (d.Length > 2 && d[0] == 'L' && d[d.Length - 1] == ';') return d.Substring(1, d.Length - 2);
            return d;
        }

        private static void Note(string o, string n, string d, HashSet<string> fl)
        {
            bool mc = o.StartsWith("net/minecraft", StringComparison.Ordinal) || o.StartsWith("com/mojang", StringComparison.Ordinal);
            if (o == "java/lang/Math" || o == "java/lang/StrictMath")
            {
                if (n == "atan2") fl.Add("atan2");
                else if (n == "toDegrees" || n == "toRadians") fl.Add("angleMath");
                else if (n == "random") fl.Add("random");
                return;
            }
            if (o == "java/util/Random" || o == "java/util/concurrent/ThreadLocalRandom" || o == "java/security/SecureRandom")
            {
                if (n == "nextGaussian") fl.Add("gaussian");
                else if (n.StartsWith("next", StringComparison.Ordinal)) fl.Add("random");
                return;
            }
            if (n == "sleep" && (o == "java/lang/Thread" || o == "java/util/concurrent/TimeUnit")) { fl.Add("sleep"); return; }
            if (o == "java/lang/System" && (n == "nanoTime" || n == "currentTimeMillis")) { fl.Add("clock"); return; }
            if (o == "java/lang/reflect/Method" && n == "invoke") { fl.Add("reflectInvoke"); return; }
            if (n == "setAccessible" && o.StartsWith("java/lang/reflect/", StringComparison.Ordinal)) { fl.Add("setAccessible"); return; }
            if (o == "java/lang/Class" && (n == "forName" || n.StartsWith("getDeclared", StringComparison.Ordinal))) { fl.Add("reflectLookup"); return; }
            if (o.StartsWith("java/lang/invoke/MethodHandles", StringComparison.Ordinal)) { fl.Add("methodHandle"); return; }
            if (o == "java/awt/Robot") { fl.Add("robot"); return; }
            if (o.StartsWith("org/lwjgl/glfw/GLFW", StringComparison.Ordinal))
            {
                if (n.StartsWith("glfwSet", StringComparison.Ordinal) && n.EndsWith("Callback", StringComparison.Ordinal)) fl.Add("glfwCallback");
                else if (n == "glfwSetCursorPos" || n == "glfwGetMouseButton" || n == "glfwGetKey" || n == "glfwSetInputMode") fl.Add("glfwInput");
                return;
            }
            if (o.StartsWith("org/lwjgl/input/", StringComparison.Ordinal)) { fl.Add("lwjgl2Input"); return; }
            if (o.StartsWith("com/github/kwhat/jnativehook", StringComparison.Ordinal) || o.StartsWith("org/jnativehook", StringComparison.Ordinal)) { fl.Add("nativeHook"); return; }
            if (o.StartsWith("java/net/", StringComparison.Ordinal) || o.StartsWith("javax/net/", StringComparison.Ordinal)) { fl.Add("net"); return; }
            if (n.IndexOf("isableDepthTest", StringComparison.Ordinal) >= 0 && (o.EndsWith("RenderSystem", StringComparison.Ordinal) || o.EndsWith("GlStateManager", StringComparison.Ordinal))) { fl.Add("depthOff"); return; }
            if (o.IndexOf("ClientTickEvent", StringComparison.Ordinal) >= 0) fl.Add("tickEvent");
            if (o.IndexOf("HudRenderCallback", StringComparison.Ordinal) >= 0 || o.IndexOf("WorldRenderEvents", StringComparison.Ordinal) >= 0 || o.IndexOf("LevelRenderEvents", StringComparison.Ordinal) >= 0
                || o.IndexOf("RenderLevelStageEvent", StringComparison.Ordinal) >= 0 || o.IndexOf("RenderGuiEvent", StringComparison.Ordinal) >= 0 || o.IndexOf("HudLayerRegistration", StringComparison.Ordinal) >= 0) fl.Add("renderEvent");
            if (o.IndexOf("KeyBindingHelper", StringComparison.Ordinal) >= 0 || (o.EndsWith("KeyMapping", StringComparison.Ordinal) && n == "<init>") || (o.EndsWith("KeyBinding", StringComparison.Ordinal) && n == "<init>")) fl.Add("keyBinding");
            if (n == "send" && (o.EndsWith("/ClientConnection", StringComparison.Ordinal) || o.EndsWith("/Connection", StringComparison.Ordinal))) { fl.Add("sendPacket"); return; }
            if (!mc) return;
            NoteDesc(o, n, d, fl);
            NoteField(o, n, fl);
            string hit;
            if (Inter.TryGetValue(n, out hit)) { fl.Add(hit); return; }
            if (n.StartsWith("method_", StringComparison.Ordinal) || (n.StartsWith("m_", StringComparison.Ordinal) && n.Length > 5)) { fl.Add("mcMethodRef"); return; }
            switch (n)
            {
                case "distanceTo": case "squaredDistanceTo": case "distanceToSqr": fl.Add("distCheck"); break;
                case "attackEntity": fl.Add("attackEntity"); break;
                case "attack": if (o.EndsWith("MultiPlayerGameMode", StringComparison.Ordinal) || o.EndsWith("InteractionManager", StringComparison.Ordinal)) fl.Add("attackEntity"); break;
                case "swingHand": case "swing": fl.Add("swing"); break;
                case "interactEntity": case "interactEntityAtLocation": case "interactAt": fl.Add("interactEntity"); break;
                case "setSprinting": fl.Add("setSprinting"); break;
                case "setVelocity": case "setDeltaMovement": case "setMotion": case "addVelocity": case "addDeltaMovement": fl.Add("setVelocity"); break;
                case "setYaw": case "setPitch": case "setYRot": case "setXRot": case "setHeadYaw": case "setYHeadRot": case "setRot": case "setRotation": case "setAngles": fl.Add("setRotation"); break;
                case "getAttackCooldownProgress": case "getAttackStrengthScale": case "getAttackCooldownProgressPerTick": fl.Add("attackCooldown"); break;
                case "clickSlot": case "handleInventoryMouseClick": case "slotClick": case "handleContainerClick": fl.Add("clickSlot"); break;
                case "sendPacket": case "sendNoEvent": case "sendUnsafe": fl.Add("sendPacket"); break;
                case "getBoundingBox": case "getBox": case "getBoundingBoxForCulling": case "getHitbox": fl.Add("boundingBox"); break;
                case "raycast": case "rayTrace": case "clip": case "getEntityHitResult": case "raycastEntity": fl.Add("raycast"); break;
                case "getEntitiesByClass": case "getEntitiesOfClass": case "getEntities": case "getOtherEntities": case "getEntitiesByType": case "getEntitiesInAABBexcluding": fl.Add("entityQuery"); break;
                case "getEyePos": case "getEyePosition": case "getCameraPosVec": fl.Add("eyePos"); break;
                case "getRotationVec": case "getRotationVector": case "getLookAngle": case "getViewVector": fl.Add("lookVec"); break;
                case "getReachDistance": case "getEntityInteractionRange": case "getBlockInteractionRange": case "getAttackRange": case "getInteractionRange": fl.Add("reachDistance"); break;
                case "setPosition": case "setPos": case "setPosRaw": case "updatePosition": case "refreshPositionAndAngles": case "moveTo": case "teleport": fl.Add("setPos"); break;
                case "setOnGround": case "setOnGroundWithKnownMovement": fl.Add("setOnGround"); break;
                case "useItem": case "interactItem": case "startUsingItem": case "useItemOn": case "interactBlock": case "useOn": fl.Add("useItem"); break;
                case "setSelectedSlot": case "changeSelectedSlot": fl.Add("swapSlot"); break;
                case "setPressed": case "setDown": fl.Add("setKeyPressed"); break;
            }
        }
        private static void NoteClass(string c, HashSet<string> fl)
        {
            if (c.IndexOf("PlayerMoveC2SPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ServerboundMovePlayerPacket", StringComparison.Ordinal) >= 0) fl.Add("movePacket");
            else if (c.IndexOf("PlayerInteractEntityC2SPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ServerboundInteractPacket", StringComparison.Ordinal) >= 0) fl.Add("interactPacket");
            else if (c.IndexOf("HandSwingC2SPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ServerboundSwingPacket", StringComparison.Ordinal) >= 0) fl.Add("swingPacket");
            else if (c.IndexOf("ClickSlotC2SPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ServerboundContainerClickPacket", StringComparison.Ordinal) >= 0) fl.Add("clickPacket");
            else if (c.IndexOf("PlayerActionC2SPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ServerboundPlayerActionPacket", StringComparison.Ordinal) >= 0) fl.Add("actionPacket");
            else if (c.IndexOf("KeepAliveC2SPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ServerboundKeepAlivePacket", StringComparison.Ordinal) >= 0) fl.Add("keepAlivePacket");
            else if (c.IndexOf("ClientCommandC2SPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ServerboundPlayerCommandPacket", StringComparison.Ordinal) >= 0) fl.Add("commandPacket");
            else if (c.IndexOf("UpdateSelectedSlotC2SPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ServerboundSetCarriedItemPacket", StringComparison.Ordinal) >= 0) fl.Add("slotPacket");
            else if (c.IndexOf("EntityVelocityUpdateS2CPacket", StringComparison.Ordinal) >= 0 || c.IndexOf("ClientboundSetEntityMotionPacket", StringComparison.Ordinal) >= 0) fl.Add("velocityPacket");
            else if (c.EndsWith("/EntityHitResult", StringComparison.Ordinal)) fl.Add("entityHitResult");
            else if (c.EndsWith("/EntityAttributeModifier", StringComparison.Ordinal) || c.EndsWith("/AttributeModifier", StringComparison.Ordinal)) fl.Add("attributeMod");
            else if (c.EndsWith("/SwordItem", StringComparison.Ordinal) || c.EndsWith("/AxeItem", StringComparison.Ordinal) || c.EndsWith("/MaceItem", StringComparison.Ordinal) || c.EndsWith("/TridentItem", StringComparison.Ordinal)) fl.Add("weaponItem");
            if (c.IndexOf("class_", StringComparison.Ordinal) >= 0)
            {
                if (HasId(c, "class_2828")) fl.Add("movePacket");
                else if (HasId(c, "class_2824")) fl.Add("interactPacket");
                else if (HasId(c, "class_2879")) fl.Add("swingPacket");
                else if (HasId(c, "class_2813")) fl.Add("clickPacket");
                else if (HasId(c, "class_2846")) fl.Add("actionPacket");
                else if (HasId(c, "class_2827")) fl.Add("keepAlivePacket");
                else if (HasId(c, "class_2848")) fl.Add("commandPacket");
                else if (HasId(c, "class_2868")) fl.Add("slotPacket");
                else if (HasId(c, "class_2743")) fl.Add("velocityPacket");
                else if (HasId(c, "class_3966")) fl.Add("entityHitResult");
                else if (HasId(c, "class_1322")) fl.Add("attributeMod");
                else if (HasId(c, "class_1829") || HasId(c, "class_1743")) fl.Add("weaponItem");
            }
        }

        private static void ReadElem(byte[] b, ref int p, Pool pool, string annType, string elemName, Parsed ps, int depth)
        {
            int tag = b[p]; p++;
            char t = (char)tag;
            if (t == 's')
            {
                string v = pool.Str(U2(b, p)); p += 2;
                if (annType == "Lorg/spongepowered/asm/mixin/Mixin;" && (elemName == "targets" || elemName == "value") && v.Length > 0) ps.MixinTargets.Add(Simple(v.Replace('.', '/')));
                else if ((annType.StartsWith("Lorg/spongepowered/asm/mixin/injection/", StringComparison.Ordinal) || annType.StartsWith("Lcom/llamalad7/mixinextras/", StringComparison.Ordinal)) && v.Length > 0)
                {
                    if (annType.EndsWith("/At;", StringComparison.Ordinal)) { if (elemName == "target") ps.Injects.Add("at:" + AtTarget(v)); }
                    else if (elemName == "method") { int pi = v.IndexOf('('); ps.Injects.Add(pi > 0 ? v.Substring(0, pi) : v); }
                }
            }
            else if (t == 'c')
            {
                string d = pool.Str(U2(b, p)); p += 2;
                if (annType == "Lorg/spongepowered/asm/mixin/Mixin;" && d.Length > 0) ps.MixinTargets.Add(Simple(DescToClass(d)));
            }
            else if (t == 'e') { p += 4; }
            else if (t == '@') { ReadAnnotation(b, ref p, pool, ps, depth + 1); }
            else if (t == '[')
            {
                int n = U2(b, p); p += 2;
                for (int i = 0; i < n; i++) ReadElem(b, ref p, pool, annType, elemName, ps, depth + 1);
            }
            else { p += 2; }
        }
        private static string AtTarget(string v)
        {
            int semi = v.IndexOf(';');
            string tail = semi >= 0 ? v.Substring(semi + 1) : v;
            int par = tail.IndexOf('(');
            if (par > 0) tail = tail.Substring(0, par);
            tail = tail.Trim();
            if (tail.Length == 0)
            {
                string cls = semi > 0 ? DescToClass(v.Substring(0, semi + 1)) : v;
                return Simple(cls);
            }
            return tail;
        }
        private static void ReadAnnotation(byte[] b, ref int p, Pool pool, Parsed ps, int depth)
        {
            if (depth > 6) throw new Exception("annotation depth");
            string type = pool.Str(U2(b, p)); p += 2;
            int pairs = U2(b, p); p += 2;
            if (type == "Lorg/spongepowered/asm/mixin/Mixin;" && depth == 0) ps.IsMixin = true;
            for (int i = 0; i < pairs; i++)
            {
                string en = pool.Str(U2(b, p)); p += 2;
                ReadElem(b, ref p, pool, type, en, ps, depth);
            }
        }
        private static void ReadAnnotations(byte[] b, int p, Pool pool, Parsed ps)
        {
            int n = U2(b, p); p += 2;
            for (int i = 0; i < n && i < 64; i++) ReadAnnotation(b, ref p, pool, ps, 0);
        }

        private static Parsed Parse(byte[] b)
        {
            Parsed ps = new Parsed();
            if (b == null || b.Length < 10 || S4(b, 0) != unchecked((int)0xCAFEBABE)) return null;
            int n = U2(b, 8);
            Pool pool = new Pool();
            pool.Tag = new int[n]; pool.A = new int[n]; pool.C = new int[n]; pool.Utf = new string[n];
            int p = 10;
            for (int i = 1; i < n; i++)
            {
                int t = b[p]; pool.Tag[i] = t; p++;
                if (t == 1) { int ul = U2(b, p); p += 2; pool.Utf[i] = Encoding.UTF8.GetString(b, p, ul); p += ul; }
                else if (t == 3 || t == 4) { p += 4; }
                else if (t == 5 || t == 6)
                {
                    if (t == 6)
                    {
                        long bits = ((long)S4(b, p) << 32) | ((long)S4(b, p + 4) & 0xFFFFFFFFL);
                        double dv = BitConverter.Int64BitsToDouble(bits);
                        if (dv > 3.05 && dv < 6.6) ps.Flags.Add("reachConst");
                    }
                    p += 8; i++;
                }
                else if (t == 7 || t == 8 || t == 16 || t == 19 || t == 20) { pool.A[i] = U2(b, p); p += 2; }
                else if (t == 9 || t == 10 || t == 11 || t == 12 || t == 17 || t == 18) { pool.A[i] = U2(b, p); pool.C[i] = U2(b, p + 2); p += 4; }
                else if (t == 15) { p += 3; }
                else return null;
            }
            p += 2;
            ps.This = pool.ClassName(U2(b, p)); p += 2;
            ps.Super = pool.ClassName(U2(b, p)); p += 2;
            int ic = U2(b, p); p += 2 + 2 * ic;
            for (int i = 1; i < n; i++)
            {
                int tg = pool.Tag[i];
                if (tg == 8)
                {
                    string s = pool.Str(pool.A[i]);
                    if (s.Length > 0 && ps.Strings.Count < 3000) ps.Strings.Add(s);
                    if (s.Length > 8 && s.Length < 80 && (s.IndexOf("interaction_range", StringComparison.Ordinal) >= 0 || s.IndexOf("attack_range", StringComparison.Ordinal) >= 0 || s.IndexOf("attack_reach", StringComparison.Ordinal) >= 0)) ps.Flags.Add("reachAttr");
                }
                else if (tg == 7)
                {
                    string c = pool.ClassName(i);
                    if (c.Length > 0)
                    {
                        NoteClass(c, ps.Flags);
                        if (ps.Refs.Count < 150 && c[0] != '[' && c != ps.This && !External(c)) ps.Refs.Add(c);
                    }
                }
            }
            try
            {
                int fc = U2(b, p); p += 2;
                for (int f = 0; f < fc; f++)
                {
                    string fn = pool.Str(U2(b, p + 2));
                    if (fn.Length > 0) ps.Fields.Add(fn);
                    p += 6;
                    int fac = U2(b, p); p += 2;
                    for (int k = 0; k < fac; k++) { int fl2 = S4(b, p + 2); p += 6 + fl2; }
                }
                int mc = U2(b, p); p += 2;
                for (int m = 0; m < mc; m++)
                {
                    string mn = pool.Str(U2(b, p + 2));
                    if (mn.Length > 0) ps.Methods.Add(mn);
                    p += 6;
                    int mac = U2(b, p); p += 2;
                    for (int k = 0; k < mac; k++)
                    {
                        string an = pool.Str(U2(b, p));
                        int al = S4(b, p + 2);
                        int body = p + 6;
                        if (an == "RuntimeInvisibleAnnotations" || an == "RuntimeVisibleAnnotations")
                        {
                            try { ReadAnnotations(b, body, pool, ps); } catch (Exception) { }
                        }
                        p = body + al;
                    }
                }
                int ca = U2(b, p); p += 2;
                for (int k = 0; k < ca; k++)
                {
                    string an2 = pool.Str(U2(b, p));
                    int al2 = S4(b, p + 2);
                    int body2 = p + 6;
                    if (an2 == "RuntimeInvisibleAnnotations" || an2 == "RuntimeVisibleAnnotations")
                    {
                        try { ReadAnnotations(b, body2, pool, ps); } catch (Exception) { }
                    }
                    p = body2 + al2;
                }
            }
            catch (Exception) { }
            for (int i = 1; i < n; i++)
            {
                int tg = pool.Tag[i];
                if (tg == 9 || tg == 10 || tg == 11)
                {
                    int cls = pool.A[i]; int nt = pool.C[i];
                    if (cls <= 0 || cls >= n || nt <= 0 || nt >= n) continue;
                    string o = pool.ClassName(cls);
                    string nm = pool.Str(pool.A[nt]);
                    if (o.Length > 0 && nm.Length > 0) Note(o, nm, pool.Str(pool.C[nt]), ps.Flags);
                }
            }
            return ps;
        }

        private static int Bump(Dictionary<string, int> d, string k, int by)
        {
            int c; d.TryGetValue(k, out c); c += by; d[k] = c; return c;
        }
        private static void Top(Dictionary<string, int> d, int max, int minScore, List<string> into)
        {
            List<KeyValuePair<string, int>> l = new List<KeyValuePair<string, int>>();
            foreach (KeyValuePair<string, int> kv in d) { if (kv.Value >= minScore) l.Add(kv); }
            l.Sort(delegate(KeyValuePair<string, int> x, KeyValuePair<string, int> y)
            {
                int c = y.Value.CompareTo(x.Value);
                return c != 0 ? c : string.CompareOrdinal(x.Key, y.Key);
            });
            for (int i = 0; i < l.Count && i < max; i++) into.Add(l[i].Key);
        }
        private bool LooksNoise(string s)
        {
            if (s.Length < 3 || s.Length > 80) return true;
            if (s.Length >= 8 && s[4] == '-' && s[0] >= '0' && s[0] <= '9') return true;
            if (s[0] == '(' || (s[0] == 'L' && s[s.Length - 1] == ';' && s.IndexOf(' ') < 0)) return true;
            int letters = 0;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c < 32) return true;
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) letters++;
            }
            return letters < 2;
        }
        private bool LooksEncrypted(string s)
        {
            if (s.Length < 6 || s.IndexOf(' ') >= 0) return false;
            int letters = 0; int high = 0;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) letters++;
                else if (c > 126 || c < 32) high++;
            }
            return high * 3 >= s.Length || letters * 100 < s.Length * 35;
        }
        private void AddString(string s, int bonus)
        {
            if (LooksNoise(s)) return;
            if (IsMapped(s)) { mappedCount++; if (mapped.Count < 8 && !mapped.Contains(s)) mapped.Add(s); return; }
            int existing;
            if (strs.TryGetValue(s, out existing)) { if (bonus > existing) strs[s] = bonus; return; }
            if (strs.Count >= 30000) return;
            int score = 1 + bonus;
            HashSet<string> f = new HashSet<string>();
            if (Vocab(s, f) > 0) { score += 20 * f.Count; foreach (string v in f) vocab.Add(v); }
            if (s.IndexOf(' ') > 0 && s.Length <= 40 && s[0] >= 'A' && s[0] <= 'Z') score += 6;
            if (LooksEncrypted(s)) { enc++; if (score < 2) return; }
            strs[s] = score;
        }
        private int ScoreName(string name, string sup, bool mixin)
        {
            int score = 0;
            HashSet<string> f = new HashSet<string>();
            if (Vocab(name, f) > 0) { score += 50; foreach (string v in f) vocab.Add(v); }
            string ls = sup == null ? "" : sup.ToLowerInvariant();
            if (ls.Length > 0 && ls != "java/lang/object")
            {
                if (ls.IndexOf("module", StringComparison.Ordinal) >= 0 || ls.IndexOf("hack", StringComparison.Ordinal) >= 0 || ls.IndexOf("cheat", StringComparison.Ordinal) >= 0
                    || ls.IndexOf("feature", StringComparison.Ordinal) >= 0 || ls.IndexOf("function", StringComparison.Ordinal) >= 0) score += 25;
                else score += 2;
            }
            string ln = name.ToLowerInvariant();
            if (ln.IndexOf("/module", StringComparison.Ordinal) >= 0 || ln.IndexOf("/hack", StringComparison.Ordinal) >= 0 || ln.IndexOf("/cheat", StringComparison.Ordinal) >= 0
                || ln.IndexOf("/combat", StringComparison.Ordinal) >= 0 || ln.IndexOf("/movement", StringComparison.Ordinal) >= 0 || ln.IndexOf("/exploit", StringComparison.Ordinal) >= 0
                || ln.IndexOf("/client/", StringComparison.Ordinal) >= 0) score += 10;
            if (mixin) score += 5;
            return score;
        }
        private static void AddBehavior(Dictionary<string, string[]> d, string rule, string cls)
        {
            string[] cur;
            if (d.TryGetValue(rule, out cur)) { cur[1] = (int.Parse(cur[1]) + 1).ToString(); return; }
            d[rule] = new string[] { cls, "1" };
        }

        public bool AddClass(byte[] b, string entryName)
        {
            Parsed ps = null;
            try { ps = Parse(b); } catch (Exception) { ps = null; }
            string name = entryName;
            if (name != null && name.EndsWith(".class", StringComparison.Ordinal)) name = name.Substring(0, name.Length - 6);
            total++;
            if (ps == null) { failed++; if (name != null) AddNameOnly(name); return false; }
            if (ps.This != null && ps.This.Length > 0) name = ps.This;
            if (name == null) name = "";
            AddNameOnly(name);
            string leaf = Simple(name);
            if (leaf.Length <= 2) shortNames++;
            if (Junk(leaf)) junkNames++;
            int score = ScoreName(name, ps.Super, ps.IsMixin);
            if (recs.Count < 6000 || score > 0)
            {
                Rec r = new Rec(); r.Name = name; r.Super = ps.Super; r.Mixin = ps.IsMixin; r.Score = score;
                if (recs.Count < 12000) recs.Add(r);
            }
            for (int i = 0; i < ps.Methods.Count; i++)
            {
                string m = ps.Methods[i];
                if (m.Length < 4 || m[0] == '<' || m.StartsWith("lambda$", StringComparison.Ordinal) || m.StartsWith("access$", StringComparison.Ordinal) || Junk(m)) continue;
                if (ps.IsMixin && mixinMethods.Count < 4000) mixinMethods.Add(m);
                if (methods.ContainsKey(m)) continue;
                if (methods.Count >= 20000) continue;
                int sc = 1;
                HashSet<string> f = new HashSet<string>();
                if (Vocab(m, f) > 0) { sc += 20 * f.Count; foreach (string v in f) vocab.Add(v); }
                if (m.Length >= 7 && m[0] >= 'a' && m[0] <= 'z') sc += 1;
                methods[m] = sc;
            }
            for (int i = 0; i < ps.Fields.Count; i++)
            {
                string fl = ps.Fields[i];
                if (fl.Length < 3 || Junk(fl) || fields.ContainsKey(fl) || fields.Count >= 10000) continue;
                int sc = 1;
                HashSet<string> f = new HashSet<string>();
                if (Vocab(fl, f) > 0) { sc += 20 * f.Count; foreach (string v in f) vocab.Add(v); }
                fields[fl] = sc;
            }
            bool hintPvp = false; bool hintClick = false;
            for (int i = 0; i < ps.Strings.Count; i++)
            {
                string s = ps.Strings[i];
                AddString(s, 0);
                if (!hintPvp || !hintClick)
                {
                    string ls = s.ToLowerInvariant();
                    if (!hintPvp) { for (int h = 0; h < PvpHints.Length; h++) { if (ls.IndexOf(PvpHints[h], StringComparison.Ordinal) >= 0) { hintPvp = true; break; } } }
                    if (!hintClick && (ls.IndexOf("click", StringComparison.Ordinal) >= 0 || ls.IndexOf("cps", StringComparison.Ordinal) >= 0 || ls.IndexOf("macro", StringComparison.Ordinal) >= 0)) hintClick = true;
                }
            }
            string lname = name.ToLowerInvariant();
            for (int h = 0; h < PvpHints.Length && !hintPvp; h++) { if (lname.IndexOf(PvpHints[h], StringComparison.Ordinal) >= 0) hintPvp = true; }
            if (!hintClick && (lname.IndexOf("click", StringComparison.Ordinal) >= 0 || lname.IndexOf("macro", StringComparison.Ordinal) >= 0)) hintClick = true;
            if (ps.IsMixin)
            {
                Bump(mixins, Simple(name), 1);
                for (int i = 0; i < ps.MixinTargets.Count; i++) Bump(targets, ps.MixinTargets[i], 2);
            }
            for (int i = 0; i < ps.Injects.Count; i++) Bump(targets, ps.Injects[i], 1);
            for (int i = 0; i < ps.Injects.Count && i < 200; i++) { string im = ps.Injects[i]; if (!im.StartsWith("at:", StringComparison.Ordinal) && mixinMethods.Count < 4000) mixinMethods.Add(im); }
            HashSet<string> fl2 = ps.Flags;
            foreach (string k in fl2) Bump(api, k, 1);
            int capW = 0;
            List<string> capKeep = new List<string>();
            foreach (string k in fl2)
            {
                if (k == "mcMethodRef" || k == "reachConst") continue;
                capKeep.Add(k);
                capW += Array.IndexOf(StrongFlags, k) >= 0 ? 2 : 1;
            }
            if (capKeep.Count >= 3 && capW >= 5 && capScore.Count < 3000)
            {
                capKeep.Sort(string.CompareOrdinal);
                capScore[name] = capW;
                capText[name] = string.Join(",", capKeep.ToArray());
            }
            Evaluate(fl2, name, hintPvp, hintClick, ps.IsMixin, behaviors);
            Track(ps, name, hintPvp, hintClick);
            return true;
        }
        private void Track(Parsed ps, string name, bool pvp, bool click)
        {
            if (ownNames.Count < 40000) ownNames.Add(name);
            if (ps.IsMixin) { if (mixinNames.Count < 600) mixinNames.Add(name); return; }
            for (int i = 0; i < ps.Refs.Count; i++) { if (refCount.Count < 30000 || refCount.ContainsKey(ps.Refs[i])) Bump(refCount, ps.Refs[i], 1); }
            int real = 0; int act = 0;
            foreach (string k in ps.Flags)
            {
                if (k == "mcMethodRef" || k == "reachConst") continue;
                real++;
                if (Array.IndexOf(ActionFlags, k) >= 0) act++;
            }
            string sup = ps.Super;
            if (sup != null && sup.Length > 0 && sup != "java/lang/Object" && (famCount.ContainsKey(sup) || famCount.Count < 5000))
            {
                Bump(famCount, sup, 1);
                if (act >= 2)
                {
                    Bump(famStrong, sup, 1);
                    List<string> ex;
                    if (!famEx.TryGetValue(sup, out ex)) { ex = new List<string>(); famEx[sup] = ex; }
                    if (ex.Count < 4) ex.Add(Simple(name));
                }
            }
            if (real == 0 || slots.Count >= 6000) return;
            Slot sl = new Slot(); sl.Name = name; sl.Flags = ps.Flags; sl.Refs = ps.Refs.ToArray(); sl.Pvp = pvp; sl.Click = click;
            slots.Add(sl);
        }
        private void AddNameOnly(string name)
        {
            if (name == null) return;
            int i = name.LastIndexOf('/');
            string pk = i > 0 ? name.Substring(0, i) : "(root)";
            string[] seg = pk.Split('/');
            string key = seg.Length > 4 ? string.Join("/", seg, 0, 4) : pk;
            Bump(pkgs, key, 1);
        }
        private void Evaluate(HashSet<string> f, string cls, bool hintPvp, bool hintClick, bool mixin, Dictionary<string, string[]> sink)
        {
            bool timing = f.Contains("clock") || f.Contains("sleep");
            bool rnd = f.Contains("random") || f.Contains("gaussian");
            bool target = f.Contains("entityQuery") || f.Contains("raycast");
            if (f.Contains("attackEntity") && target && (timing || rnd || f.Contains("attackCooldown")))
                AddBehavior(sink, "Attacks entities from code with its own targeting and timing (aura / triggerbot behaviour)", cls);
            if (f.Contains("setRotation") && f.Contains("atan2") && (target || f.Contains("eyePos") || f.Contains("lookVec")))
                AddBehavior(sink, "Computes the angle to a target and rotates the player (aim assist / aimbot behaviour)", cls);
            if (f.Contains("movePacket") && f.Contains("sendPacket") && (f.Contains("setVelocity") || f.Contains("setPos") || f.Contains("setOnGround")))
                AddBehavior(sink, "Sends its own movement packets while moving the player (fly / nofall / blink / phase behaviour)", cls);
            if (f.Contains("interactPacket") && f.Contains("sendPacket") && target)
                AddBehavior(sink, "Sends attack/interact packets by hand (reach / aura / criticals behaviour)", cls);
            if ((f.Contains("clickSlot") || f.Contains("clickPacket")) && (timing || rnd) && hintPvp)
                AddBehavior(sink, "Moves inventory items by code with timed delays (auto totem / auto armor / inventory macro behaviour)", cls);
            if (f.Contains("depthOff") && f.Contains("entityQuery") && f.Contains("boundingBox"))
                AddBehavior(sink, "Draws boxes over entities with depth testing off (ESP / wallhack behaviour)", cls);
            else if (f.Contains("renderEvent") && f.Contains("entityQuery") && f.Contains("boundingBox") && f.Contains("eyePos"))
                AddBehavior(sink, "Draws lines/boxes to entities from the eye position (ESP / tracer behaviour)", cls);
            if ((f.Contains("robot") || f.Contains("glfwInput") || f.Contains("nativeHook") || f.Contains("setKeyPressed")) && rnd && timing && hintClick)
                AddBehavior(sink, "Generates input on its own with random delays (autoclicker / jitter / macro behaviour)", cls);
            bool slot = f.Contains("swapSlot") || f.Contains("slotPacket") || f.Contains("slotField");
            bool cross = f.Contains("crosshair");
            bool timed = timing || rnd || f.Contains("attackCooldown") || f.Contains("tickEvent");
            if (slot && f.Contains("attackEntity"))
                AddBehavior(sink, "Switches hotbar slot and attacks in one class (weapon swap / mace swap behaviour)", cls);
            else if (slot && f.Contains("weaponItem") && (target || cross || f.Contains("attackCooldown")))
                AddBehavior(sink, "Picks a weapon item and switches the hotbar slot around attacks (auto weapon / auto swap behaviour)", cls);
            else if (f.Contains("slotPacket") && f.Contains("sendPacket") && (cross || target))
                AddBehavior(sink, "Sends hotbar slot packets while targeting entities (silent swap / mace swap behaviour)", cls);
            if (f.Contains("attackEntity") && cross && f.Contains("entityHitResult") && timed)
                AddBehavior(sink, "Reads the entity under the crosshair and attacks it from code (triggerbot behaviour)", cls);
            if ((f.Contains("attackEntity") || f.Contains("interactPacket")) && f.Contains("distCheck") && f.Contains("reachConst") && target)
                AddBehavior(sink, "Attacks entities using its own distance limit above vanilla reach (reach behaviour)", cls);
            if (f.Contains("reachAttr") && f.Contains("attributeMod"))
                AddBehavior(sink, "Changes the player's reach attribute from code (reach behaviour)", cls);
            if (mixin && f.Contains("reachDistance"))
                AddBehavior(sink, "Hooks the interaction/reach distance (reach behaviour)", cls);
            if (f.Contains("useItem") && f.Contains("setRotation") && slot && timed && !mixin)
                AddBehavior(sink, "Places blocks while rotating and switching hotbar slots on a timer (scaffold / tower behaviour)", cls);
            if (f.Contains("actionPacket") && f.Contains("sendPacket") && timed && !mixin)
                AddBehavior(sink, "Sends block-break action packets by hand on a timer (nuker / fast break / packet mine behaviour)", cls);
            if (f.Contains("movePacket") && f.Contains("sendPacket") && f.Contains("attackEntity"))
                AddBehavior(sink, "Sends position packets around attacks (criticals behaviour)", cls);
            if (f.Contains("setSprinting") && f.Contains("attackEntity") && (f.Contains("commandPacket") || f.Contains("setKeyPressed")))
                AddBehavior(sink, "Toggles sprint around attacks (W-tap / sprint reset behaviour)", cls);
            if (f.Contains("attackEntity") && target && f.Contains("useItem") && hintPvp)
                AddBehavior(sink, "Places and attacks crystals or anchors from code (auto crystal / anchor aura behaviour)", cls);
            if (f.Contains("useItem") && slot && hintPvp && timed && !f.Contains("attackEntity"))
                AddBehavior(sink, "Switches hotbar slots and uses items on a timer (auto pearl / firework / potion / totem macro behaviour)", cls);
            if (f.Contains("setVelocity") && f.Contains("lookVec") && f.Contains("tickEvent") && !mixin)
                AddBehavior(sink, "Sets the player's velocity along the view direction every tick (fly / speed / boost behaviour)", cls);
            if ((f.Contains("clickSlot") || f.Contains("clickPacket")) && rnd && timing && !hintPvp)
                AddBehavior(sink, "Clicks container slots by code with random delays (chest stealer / inventory manager behaviour)", cls);
            if (f.Contains("setRotation") && target && rnd && timed && !mixin)
                AddBehavior(sink, "Rotates toward targets with random smoothing (aim assist / humanized aim behaviour)", cls);
            if (f.Contains("offhandSwap") && f.Contains("sendPacket") && (timed || rnd) && !mixin)
                AddBehavior(sink, "Swaps the off-hand item by packet on a timer (auto totem / offhand macro behaviour)", cls);
            if (f.Contains("stepHeight") && f.Contains("tickEvent") && !mixin)
                AddBehavior(sink, "Changes the player's step height every tick (step behaviour)", cls);
        }

        public void AddLang(string text)
        {
            if (string.IsNullOrEmpty(text) || text.Length > 600000) return;
            try
            {
                MatchCollection mc = Regex.Matches(text, "\"((?:[^\"\\\\]|\\\\.){1,70})\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.){2,80})\"");
                int n = 0;
                foreach (Match m in mc)
                {
                    if (n++ > 800) break;
                    HashSet<string> f = new HashSet<string>();
                    if (Vocab(m.Groups[1].Value, f) > 0) { foreach (string v in f) vocab.Add(v); }
                    AddString(m.Groups[2].Value.Replace("\\\"", "\"").Replace("\\\\", "\\"), 8);
                }
            }
            catch (Exception) { }
        }

        public void Merge(ProfileBuilder o)
        {
            if (o == null) return;
            total += o.total; shortNames += o.shortNames; junkNames += o.junkNames; enc += o.enc; mappedCount += o.mappedCount; failed += o.failed;
            for (int i = 0; i < o.recs.Count && recs.Count < 12000; i++) recs.Add(o.recs[i]);
            foreach (KeyValuePair<string, int> kv in o.pkgs) Bump(pkgs, kv.Key, kv.Value);
            foreach (KeyValuePair<string, int> kv in o.methods) { if (!methods.ContainsKey(kv.Key) && methods.Count < 20000) methods[kv.Key] = kv.Value; }
            foreach (KeyValuePair<string, int> kv in o.fields) { if (!fields.ContainsKey(kv.Key) && fields.Count < 10000) fields[kv.Key] = kv.Value; }
            foreach (KeyValuePair<string, int> kv in o.strs) { if (!strs.ContainsKey(kv.Key) && strs.Count < 30000) strs[kv.Key] = kv.Value; }
            foreach (KeyValuePair<string, int> kv in o.mixins) Bump(mixins, kv.Key, kv.Value);
            foreach (KeyValuePair<string, int> kv in o.targets) Bump(targets, kv.Key, kv.Value);
            foreach (KeyValuePair<string, int> kv in o.api) Bump(api, kv.Key, kv.Value);
            foreach (string v in o.vocab) vocab.Add(v);
            foreach (string m in o.mixinMethods) { if (mixinMethods.Count < 4000) mixinMethods.Add(m); }
            foreach (string s in o.mapped) { if (mapped.Count < 8 && !mapped.Contains(s)) mapped.Add(s); }
            foreach (KeyValuePair<string, int> kv in o.capScore) { if (!capScore.ContainsKey(kv.Key) && capScore.Count < 3000) { capScore[kv.Key] = kv.Value; capText[kv.Key] = o.capText[kv.Key]; } }
        }

        private Dictionary<string, string[]> CrossClass()
        {
            Dictionary<string, string[]> found = new Dictionary<string, string[]>();
            if (slots.Count < 2) return found;
            Dictionary<string, Slot> byName = new Dictionary<string, Slot>();
            for (int i = 0; i < slots.Count; i++) { if (!byName.ContainsKey(slots[i].Name)) byName[slots[i].Name] = slots[i]; }
            int budget = 4000;
            for (int i = 0; i < slots.Count && budget > 0; i++)
            {
                Slot a = slots[i];
                if (a.Refs.Length == 0) continue;
                budget--;
                HashSet<string> u = new HashSet<string>(a.Flags);
                bool pvp = a.Pvp; bool click = a.Click;
                List<string> used = new List<string>();
                for (int r = 0; r < a.Refs.Length && used.Count < 6; r++)
                {
                    Slot h;
                    if (!byName.TryGetValue(a.Refs[r], out h) || object.ReferenceEquals(h, a)) continue;
                    int rc;
                    if (refCount.TryGetValue(h.Name, out rc) && rc > 15) continue;
                    foreach (string k in h.Flags) u.Add(k);
                    if (h.Pvp) pvp = true;
                    if (h.Click) click = true;
                    used.Add(Simple(h.Name));
                }
                if (used.Count == 0) continue;
                Dictionary<string, string[]> tmp = new Dictionary<string, string[]>();
                Evaluate(u, a.Name, pvp, click, false, tmp);
                foreach (KeyValuePair<string, string[]> kv in tmp)
                {
                    if (behaviors.ContainsKey(kv.Key) || found.ContainsKey(kv.Key)) continue;
                    found[kv.Key] = new string[] { Simple(a.Name) + " + " + string.Join(" + ", used.ToArray()), "1" };
                }
            }
            return found;
        }
        public List<string[]> Hierarchy()
        {
            List<string[]> res = new List<string[]>();
            foreach (KeyValuePair<string, int> kv in famCount)
            {
                if (kv.Value < 8 || !ownNames.Contains(kv.Key)) continue;
                int st;
                if (!famStrong.TryGetValue(kv.Key, out st) || st < 3) continue;
                List<string> ex;
                famEx.TryGetValue(kv.Key, out ex);
                res.Add(new string[] { Simple(kv.Key), kv.Value.ToString(), st.ToString(), ex == null ? "" : string.Join(", ", ex.ToArray()) });
                if (res.Count >= 3) break;
            }
            return res;
        }
        public string[] MixinNames() { return mixinNames.ToArray(); }
        public int Total { get { return total; } }
        public int VocabCount { get { return vocab.Count; } }
        public int MappedCount { get { return mappedCount; } }
        public string[] VocabTerms() { List<string> l = new List<string>(vocab); l.Sort(string.CompareOrdinal); return l.ToArray(); }

        public List<string[]> Behaviors()
        {
            List<string[]> res = new List<string[]>();
            foreach (KeyValuePair<string, string[]> kv in behaviors)
            {
                int n = int.Parse(kv.Value[1]);
                string detail = kv.Value[0] + (n > 1 ? " (+" + (n - 1) + " more)" : "");
                res.Add(new string[] { kv.Key, detail });
            }
            int cxn = 0;
            foreach (KeyValuePair<string, string[]> cx in CrossClass())
            {
                if (cxn++ >= 4) break;
                res.Add(new string[] { cx.Key, cx.Value[0] + " (behaviour split across classes)" });
            }
            Regex kb = new Regex("(?i)(velocity|knockback|takeknockback|applyknockback|deltamovement)");
            Regex reach = new Regex("(?i)(getreachdistance|interactionrange|reachdistance|getattackrange|extendreach|entityreach|updatetargetedentity|method_3190|method_2904|method_55754|method_55755)");
            Regex cool = new Regex("(?i)(itemusecooldown|blockbreakingcooldown|attackcooldown|dodoattack|doitemuse|rightclickdelay|handleblockbreaking|updateblockbreakingprogress|hitdelay|blockhitdelay)");
            Regex onground = new Regex("(?i)(isonground|setonground|onground)");
            string kbHit = null; string reachHit = null; string coolHit = null; string groundHit = null;
            List<string> probe = new List<string>(targets.Keys);
            foreach (string m in mixinMethods) probe.Add(m);
            foreach (string p in probe)
            {
                string q = p.StartsWith("at:", StringComparison.Ordinal) ? p.Substring(3) : p;
                if (kbHit == null && kb.IsMatch(q)) kbHit = q;
                if (reachHit == null && reach.IsMatch(q)) reachHit = q;
                if (coolHit == null && cool.IsMatch(q)) coolHit = q;
                if (groundHit == null && onground.IsMatch(q)) groundHit = q;
            }
            if (kbHit != null && mixins.Count > 0) res.Add(new string[] { "Hooks knockback/velocity handling with a mixin (anti-knockback / velocity behaviour)", kbHit });
            if (reachHit != null && mixins.Count > 0) res.Add(new string[] { "Hooks the interaction/reach distance with a mixin (reach behaviour)", reachHit });
            if (mixins.Count > 0)
            {
                for (int mr = 0; mr < MixinRules.Length; mr++)
                {
                    string need = MixinRules[mr][2];
                    if (need.Length > 0)
                    {
                        bool allGroups = true;
                        string[] groups = need.Split(';');
                        for (int g = 0; g < groups.Length && allGroups; g++)
                        {
                            bool anyNeed = false;
                            string[] nf = groups[g].Split(',');
                            for (int q = 0; q < nf.Length; q++) { if (api.ContainsKey(nf[q])) { anyNeed = true; break; } }
                            if (!anyNeed) allGroups = false;
                        }
                        if (!allGroups) continue;
                    }
                    Regex rr = new Regex(MixinRules[mr][0]);
                    string rhit = null;
                    foreach (string p2 in probe) { string q2 = p2.StartsWith("at:", StringComparison.Ordinal) ? p2.Substring(3) : p2; if (rr.IsMatch(q2)) { rhit = q2; break; } }
                    if (rhit != null) res.Add(new string[] { MixinRules[mr][1], rhit });
                }
            }
            if (api.ContainsKey("velocityPacket") && mixins.Count > 0) res.Add(new string[] { "Hooks velocity packets with a mixin (anti-knockback / velocity behaviour)", "EntityVelocityUpdate packet" });
            if (coolHit != null && mixins.Count > 0) res.Add(new string[] { "Hooks use/attack/break cooldowns with a mixin (fast place / fast break / autoclicker behaviour)", coolHit });
            if (groundHit != null && mixins.Count > 0 && api.ContainsKey("movePacket")) res.Add(new string[] { "Hooks the on-ground flag and sends movement packets (nofall / fly behaviour)", groundHit });
            int refl = 0;
            if (api.ContainsKey("reflectInvoke")) refl++;
            if (api.ContainsKey("setAccessible")) refl++;
            if (api.ContainsKey("reflectLookup")) refl++;
            if (mappedCount >= 3 && refl >= 1)
                res.Add(new string[] { "Looks up obfuscated Minecraft names by string (field_/method_/f_/m_) and uses reflection - a way to avoid mixins and scanners", mappedCount + " such strings" });
            return res;
        }

        private static void Esc(StringBuilder sb, string s)
        {
            sb.Append('"');
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '"') sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c < 32 || c > 126) sb.Append("\\u").Append(((int)c).ToString("x4"));
                else sb.Append(c);
            }
            sb.Append('"');
        }
        private static void StrArr(StringBuilder sb, string key, List<string> items, int maxLen)
        {
            sb.Append('"').Append(key).Append("\":[");
            for (int i = 0; i < items.Count; i++)
            {
                if (i > 0) sb.Append(',');
                string s = items[i];
                if (s.Length > maxLen) s = s.Substring(0, maxLen);
                Esc(sb, s);
            }
            sb.Append(']');
        }

        public string Build(int maxChars)
        {
            int cClasses = 80, cMethods = 90, cFields = 60, cStrings = 120, cTargets = 40, cMixins = 40;
            string json = null;
            for (int round = 0; round < 8; round++)
            {
                json = BuildOnce(cClasses, cMethods, cFields, cStrings, cTargets, cMixins);
                if (json.Length <= maxChars) break;
                cClasses = cClasses * 3 / 4; cMethods = cMethods * 3 / 4; cFields = cFields * 3 / 4; cStrings = cStrings * 3 / 4; cTargets = cTargets * 3 / 4; cMixins = cMixins * 3 / 4;
            }
            return json;
        }
        private string BuildOnce(int cClasses, int cMethods, int cFields, int cStrings, int cTargets, int cMixins)
        {
            StringBuilder sb = new StringBuilder(9000);
            sb.Append('{');
            List<KeyValuePair<string, int>> pk = new List<KeyValuePair<string, int>>(pkgs);
            pk.Sort(delegate(KeyValuePair<string, int> x, KeyValuePair<string, int> y)
            {
                int c = y.Value.CompareTo(x.Value);
                return c != 0 ? c : string.CompareOrdinal(x.Key, y.Key);
            });
            sb.Append("\"packages\":[");
            for (int i = 0; i < pk.Count && i < 16; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append("{\"p\":"); Esc(sb, pk[i].Key.Length > 100 ? pk[i].Key.Substring(0, 100) : pk[i].Key); sb.Append(",\"n\":").Append(pk[i].Value).Append('}');
            }
            sb.Append("],");
            List<Rec> sorted = new List<Rec>(recs);
            sorted.Sort(delegate(Rec x, Rec y)
            {
                int c = y.Score.CompareTo(x.Score);
                return c != 0 ? c : string.CompareOrdinal(x.Name, y.Name);
            });
            List<string> cl = new List<string>();
            for (int i = 0; i < sorted.Count && cl.Count < cClasses; i++)
            {
                Rec r = sorted[i];
                if (r.Mixin) continue;
                string s = r.Name;
                if (r.Super != null && r.Super.Length > 0 && r.Super != "java/lang/Object") s = s + " < " + r.Super;
                cl.Add(s);
            }
            StrArr(sb, "classes", cl, 90); sb.Append(',');
            List<string> mx = new List<string>(); Top(mixins, cMixins, 1, mx);
            StrArr(sb, "mixins", mx, 90); sb.Append(',');
            List<string> tg = new List<string>(); Top(targets, cTargets, 1, tg);
            StrArr(sb, "mixinTargets", tg, 100); sb.Append(',');
            List<string> ml = new List<string>(); Top(methods, cMethods, 1, ml);
            StrArr(sb, "methods", ml, 50); sb.Append(',');
            List<string> fd = new List<string>(); Top(fields, cFields, 1, fd);
            StrArr(sb, "fields", fd, 50); sb.Append(',');
            List<string> st = new List<string>(); Top(strs, cStrings, 1, st);
            StrArr(sb, "strings", st, 60); sb.Append(',');
            List<string> cp = new List<string>();
            List<KeyValuePair<string, int>> capList = new List<KeyValuePair<string, int>>(capScore);
            capList.Sort(delegate(KeyValuePair<string, int> x, KeyValuePair<string, int> y)
            {
                int c = y.Value.CompareTo(x.Value);
                return c != 0 ? c : string.CompareOrdinal(x.Key, y.Key);
            });
            for (int i = 0; i < capList.Count && cp.Count < Math.Max(5, cTargets / 2); i++) cp.Add(capList[i].Key + ": " + capText[capList[i].Key]);
            StrArr(sb, "capabilities", cp, 170); sb.Append(',');
            sb.Append("\"mappedReflection\":{\"count\":").Append(mappedCount).Append(',');
            StrArr(sb, "sample", mapped, 40); sb.Append("},");
            sb.Append("\"api\":{");
            List<KeyValuePair<string, int>> ap = new List<KeyValuePair<string, int>>(api);
            ap.Sort(delegate(KeyValuePair<string, int> x, KeyValuePair<string, int> y) { return string.CompareOrdinal(x.Key, y.Key); });
            for (int i = 0; i < ap.Count && i < 60; i++)
            {
                if (i > 0) sb.Append(',');
                Esc(sb, ap[i].Key); sb.Append(':').Append(ap[i].Value);
            }
            sb.Append("},");
            List<string> vl = new List<string>(vocab); vl.Sort(string.CompareOrdinal);
            StrArr(sb, "vocab", vl, 40); sb.Append(',');
            int pctShort = total > 0 ? (int)Math.Round(100.0 * shortNames / total) : 0;
            int pctJunk = total > 0 ? (int)Math.Round(100.0 * junkNames / total) : 0;
            sb.Append("\"obfuscation\":{\"shortNamePct\":").Append(pctShort).Append(",\"junkNamePct\":").Append(pctJunk).Append(",\"encryptedStrings\":").Append(enc).Append("},");
            sb.Append("\"totalClasses\":").Append(total);
            sb.Append('}');
            return sb.ToString();
        }
    }
}
'@

$script:ProfilerOk = $false
$script:ProfilerError = $null
try {
    if (-not ('CactusHacksDetector.ProfileBuilder' -as [type])) { Add-Type -TypeDefinition $script:ProfilerSource -Language CSharp -ErrorAction Stop }
    $script:ProfilerOk = $true
} catch { $script:ProfilerError = $_.Exception.Message }

$script:IsAdmin = $false
try {
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $script:IsAdmin = (New-Object Security.Principal.WindowsPrincipal($wid)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
$script:NowUtc = (Get-Date).ToUniversalTime()
$script:WindowStart = $script:NowUtc.AddHours(-[math]::Max(1, $LookbackHours))
$script:Sys = New-Object System.Collections.Generic.List[object]
$script:SysSeen = @{}
$script:ModStatus = New-Object System.Collections.Generic.List[object]
$script:Keybinds = New-Object System.Collections.Generic.List[object]
$script:GameDirs = New-Object System.Collections.Generic.List[string]
$script:ModuleNote = $null
$script:ModuleSkipped = $false

function Write-Line([string]$Text, [string]$Color = 'Gray') { Write-Host $Text -ForegroundColor $Color }

$script:RunSw = [Diagnostics.Stopwatch]::StartNew()
function Format-Span([TimeSpan]$t) { '{0:00}:{1:00}' -f [int][math]::Floor($t.TotalMinutes), $t.Seconds }

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ('=' * 76) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan -NoNewline
    Write-Host ('   [running ' + (Format-Span $script:RunSw.Elapsed) + ']') -ForegroundColor DarkGray
    Write-Host ('=' * 76) -ForegroundColor DarkCyan
}

function Hide-User([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    try {
        if ($env:USERPROFILE) { $out = $out.Replace($env:USERPROFILE, '%USERPROFILE%') }
        if ($env:USERNAME -and $env:USERNAME.Length -ge 3) { $out = [regex]::Replace($out, [regex]::Escape($env:USERNAME), '<user>', 'IgnoreCase') }
        if ($env:COMPUTERNAME -and $env:COMPUTERNAME.Length -ge 3) { $out = [regex]::Replace($out, [regex]::Escape($env:COMPUTERNAME), '<pc>', 'IgnoreCase') }
    } catch {}
    return $out
}

$script:RedactRx = @(
    (New-Object Regex('(?i)(password|passwd|pwd|passphrase|token|secret|api[-_]?key|apikey|authorization|bearer|session[-_]?id|access[-_]?token)(\s*[=:]\s*|\s+)("[^"]*"|''[^'']*''|\S+)', 'Compiled')),
    (New-Object Regex('(?i)(-password|--password|-p)\s+("[^"]*"|\S+)', 'Compiled')),
    (New-Object Regex('[MNO][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,}', 'Compiled')),
    (New-Object Regex('[A-Za-z0-9+/_\-]{40,}={0,2}', 'Compiled')),
    (New-Object Regex('[\w.+\-]+@[\w\-]+\.[\w.\-]+', 'Compiled'))
)
function Redact-Text([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    $t = $script:RedactRx[0].Replace($t, '$1=<redacted>')
    $t = $script:RedactRx[1].Replace($t, '$1 <redacted>')
    $t = $script:RedactRx[2].Replace($t, '<token>')
    $t = $script:RedactRx[3].Replace($t, '<long-string>')
    $t = $script:RedactRx[4].Replace($t, '<email>')
    return $t
}

function Limit-Text([string]$Text, [int]$Max = 300) {
    if ($null -eq $Text) { return '' }
    $t = ($Text -replace '[\x00-\x1F\x7F]', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + '...' }
    return $t
}

function Get-FileHashSafe([string]$Path, [string]$Algo) {
    try { return (Get-FileHash -LiteralPath $Path -Algorithm $Algo -ErrorAction Stop).Hash.ToLower() }
    catch { return $null }
}

function Test-InWindow($Time) {
    if ($null -eq $Time) { return $false }
    try {
        if ($Time -is [datetime]) { return ($Time.ToUniversalTime() -ge $script:WindowStart) }
        $t = [datetime]::Parse([string]$Time, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        return ($t.ToUniversalTime() -ge $script:WindowStart)
    } catch { return $false }
}

function Add-Sys([string]$Sev, [string]$Cat, [string]$Rule, [string]$Detail, $Time, [string]$Source) {
    $t = $null
    if ($Time -is [datetime]) { try { $t = $Time.ToUniversalTime().ToString('o') } catch {} }
    elseif ($Time) { $t = [string]$Time }
    $d = Limit-Text (Redact-Text (Hide-User $Detail)) 300
    $key = "$Cat|$Rule|$d"
    if ($script:SysSeen.ContainsKey($key)) { return }
    $script:SysSeen[$key] = $true
    [void]$script:Sys.Add([pscustomobject]@{ Severity = $Sev; Category = $Cat; Rule = $Rule; Detail = $d; Time = $t; Source = $Source })
}

function Set-ModuleSkipped([string]$Why) { $script:ModuleSkipped = $true; $script:ModuleNote = $Why }
function Set-ModuleNote([string]$Why) { if (-not $script:ModuleNote) { $script:ModuleNote = $Why } }

function Invoke-Module([string]$Name, [scriptblock]$Block, [switch]$NeedsAdmin) {
    $before = $script:Sys.Count
    $script:ModuleNote = $null; $script:ModuleSkipped = $false
    $status = 'ok'
    if ($NeedsAdmin -and -not $script:IsAdmin) { Set-ModuleNote 'partial: run as Administrator for full coverage' }
    try { & $Block } catch { $status = 'error'; $script:ModuleNote = Limit-Text (Hide-User $_.Exception.Message) 160 }
    if ($script:ModuleSkipped) { $status = 'skipped' }
    $n = $script:Sys.Count - $before
    [void]$script:ModStatus.Add([pscustomobject]@{ Name = $Name; Status = $status; Note = $script:ModuleNote; Findings = $n })
    $color = switch ($status) { 'ok' { 'Green' } 'skipped' { 'DarkYellow' } default { 'Yellow' } }
    $tail = ''; if ($script:ModuleNote) { $tail = "  ($($script:ModuleNote))" }
    Write-Host ('  [{0,-7}] {1}  - {2} finding(s){3}   [{4}]' -f $status, $Name, $n, $tail, (Format-Span $script:RunSw.Elapsed)) -ForegroundColor $color
}

function New-Finding($Sev, $Cat, $Rule, $Detail, $Where) {
    [pscustomobject]@{ Severity = $Sev; Category = $Cat; Rule = $Rule; Detail = $Detail; Where = $Where }
}

function Get-EventsSafe([hashtable]$Filter, [int]$Max = 300) {
    try { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) } catch { return @() }
}

$script:GlfwKeys = @{}
$script:LwjglKeys = @{}
function Initialize-KeyTables {
    $g = $script:GlfwKeys
    foreach ($c in 65..90) { $g[$c] = [string][char]$c }
    foreach ($c in 48..57) { $g[$c] = [string][char]$c }
    for ($i = 1; $i -le 25; $i++) { $g[289 + $i] = "F$i" }
    for ($i = 0; $i -le 9; $i++) { $g[320 + $i] = "Keypad $i" }
    $named = @{
        32 = 'Space'; 39 = "'"; 44 = ','; 45 = '-'; 46 = '.'; 47 = '/'; 59 = ';'; 61 = '='; 91 = '['; 92 = '\'; 93 = ']'; 96 = '`'
        256 = 'Escape'; 257 = 'Enter'; 258 = 'Tab'; 259 = 'Backspace'; 260 = 'Insert'; 261 = 'Delete'
        262 = 'Right Arrow'; 263 = 'Left Arrow'; 264 = 'Down Arrow'; 265 = 'Up Arrow'; 266 = 'Page Up'; 267 = 'Page Down'
        268 = 'Home'; 269 = 'End'; 280 = 'Caps Lock'; 281 = 'Scroll Lock'; 282 = 'Num Lock'; 283 = 'Print Screen'; 284 = 'Pause'
        330 = 'Keypad .'; 331 = 'Keypad /'; 332 = 'Keypad *'; 333 = 'Keypad -'; 334 = 'Keypad +'; 335 = 'Keypad Enter'; 336 = 'Keypad ='
        340 = 'Left Shift'; 341 = 'Left Control'; 342 = 'Left Alt'; 343 = 'Left Super'
        344 = 'Right Shift'; 345 = 'Right Control'; 346 = 'Right Alt'; 347 = 'Right Super'; 348 = 'Menu'
    }
    foreach ($k in $named.Keys) { $g[[int]$k] = $named[$k] }

    $l = $script:LwjglKeys
    $rows = @{ 16 = 'QWERTYUIOP'; 30 = 'ASDFGHJKL'; 44 = 'ZXCVBNM' }
    foreach ($start in $rows.Keys) { $s = $rows[$start]; for ($i = 0; $i -lt $s.Length; $i++) { $l[[int]$start + $i] = [string]$s[$i] } }
    for ($i = 2; $i -le 10; $i++) { $l[$i] = [string]($i - 1) }
    $l[11] = '0'
    for ($i = 59; $i -le 68; $i++) { $l[$i] = 'F' + ($i - 58) }
    $l[87] = 'F11'; $l[88] = 'F12'
    $lnamed = @{
        1 = 'Escape'; 12 = '-'; 13 = '='; 14 = 'Backspace'; 15 = 'Tab'; 26 = '['; 27 = ']'; 28 = 'Enter'; 29 = 'Left Control'
        39 = ';'; 40 = "'"; 41 = '`'; 42 = 'Left Shift'; 43 = '\'; 51 = ','; 52 = '.'; 53 = '/'; 54 = 'Right Shift'
        55 = 'Numpad *'; 56 = 'Left Alt'; 57 = 'Space'; 58 = 'Caps Lock'; 69 = 'Num Lock'; 70 = 'Scroll Lock'
        71 = 'Numpad 7'; 72 = 'Numpad 8'; 73 = 'Numpad 9'; 74 = 'Numpad -'; 75 = 'Numpad 4'; 76 = 'Numpad 5'; 77 = 'Numpad 6'
        78 = 'Numpad +'; 79 = 'Numpad 1'; 80 = 'Numpad 2'; 81 = 'Numpad 3'; 82 = 'Numpad 0'; 83 = 'Numpad .'
        156 = 'Numpad Enter'; 157 = 'Right Control'; 181 = 'Numpad /'; 184 = 'Right Alt'
        199 = 'Home'; 200 = 'Up Arrow'; 201 = 'Page Up'; 203 = 'Left Arrow'; 205 = 'Right Arrow'; 207 = 'End'
        208 = 'Down Arrow'; 209 = 'Page Down'; 210 = 'Insert'; 211 = 'Delete'
    }
    foreach ($k in $lnamed.Keys) { $l[[int]$k] = $lnamed[$k] }
}
Initialize-KeyTables

function Format-KeyCode([int]$Code, [int]$Major, $Caps) {
    $g = $script:GlfwKeys[$Code]; $l = $script:LwjglKeys[$Code]
    $useL = ($Caps -contains 'lwjgl2'); $useG = (($Caps -contains 'glfw') -or ($Major -ge 55))
    if ($useL -and $l) { return [string]$l }
    if ($useG -and $g) { return [string]$g }
    if ($g -and $l -and ($g -ne $l)) { return "$g (GLFW) or $l (LWJGL2)" }
    if ($g) { return [string]$g }
    if ($l) { return [string]$l }
    return "key code $Code"
}

function Convert-OptionKey([string]$v) {
    $ti = (Get-Culture).TextInfo
    if ($v -match '^key\.keyboard\.(.+)$') {
        if ($Matches[1] -eq 'unknown') { return 'Unbound' }
        return $ti.ToTitleCase(($Matches[1] -replace '\.', ' '))
    }
    if ($v -match '^key\.mouse\.(.+)$') { return 'Mouse ' + $ti.ToTitleCase($Matches[1]) }
    if ($v -match '^-?\d+$') {
        $n = [int]$v
        if ($n -eq -100) { return 'Left Mouse' }
        if ($n -eq -99) { return 'Right Mouse' }
        if ($n -eq -98) { return 'Middle Mouse' }
        if ($n -lt 0) { return 'Mouse ' + ($n + 101) }
        if ($n -eq 0) { return 'Unbound' }
        $l = $script:LwjglKeys[$n]; if ($l) { return [string]$l }
        return "key code $n"
    }
    return $v
}

function Get-HackKind([string]$Name, [string]$Cat) {
    $n = ("$Name $Cat").ToLower()
    if ($n -match 'kill|aura|trigger|aim|crystal|anchor|totem|clicker|pearl|reach|velocity|knockback|criticals|hitbox|jitter|wtap|w-tap|combat|fight|sword|armor|hit') { return 'Combat' }
    if ($n -match 'fly|speed|bhop|bunny|jesus|nofall|no-fall|strafe|step|spider|longjump|highjump|airjump|phase|blink|sprint|motion|movement|slow') { return 'Movement' }
    if ($n -match 'esp|xray|x-ray|tracer|nametag|fullbright|freecam|render|visual|chams|wallhack') { return 'Render' }
    if ($n -match 'scaffold|nuker|fastplace|fastbreak|fast-place|fast-break|bed|world|chest|steal|inventory') { return 'World/Utility' }
    return 'Other'
}

$Sig = @{

    Clients = '(?i)(liquid[-_ ]?bounce|meteor[-_ ]?client|meteordevelopment|(?<![a-z])wurst(?:[-_ ]?client)?(?![a-z])|net/wurstclient|aristois|impact[-_ ]?client|future[-_ ]?client|rusher[-_ ]?hack|thunder[-_ ]?hack|pandaware|(?<![a-z])asteria(?![a-z])|(?<![a-z])xenon[-_ ]?client|vape[-_ ]?(?:v4|lite|client)|(?<![a-z])vapev4|doomsday[-_ ]?client|prestige[-_ ]?client|(?<![a-z])konas(?![a-z])|3arthh4ck|salhack|bleach[-_ ]?hack|coffee[-_ ]?client|inertia[-_ ]?client|sigma[-_ ]?client|novoline|exhibition[-_ ]?client|astolfo[-_ ]?(?:client|hack|utils|ware)|(?:club|dev|me|net|com)[/.]astolfo|raven[-_ ]?b[0-9s]|lunar[-_ ]?cheat|fdp[-_ ]?client|(?<![a-z])nodus(?![a-z])|kami[-_ ]?blue|forgehax|tenacity[-_ ]?client|rise[-_ ]?client|slinky[-_ ]?client|moonlight[-_ ]?client|zeroday[-_ ]?client|dortware|hanabi[-_ ]?client|augustus[-_ ]?client|trollhack|gamesense[-_ ]?client|xulu[-_ ]?client|cosmos[-_ ]?client|boze[-_ ]?client|opai[-_ ]?client|cat[-_ ]?lean|argon[-_ ]?client|gypsy[-_ ]?client|virgin[-_ ]?client|grim[-_ ]?client|nova[-_ ]?client|(?<![a-z])hellion(?![a-z])|phobos[-_ ]?(?:client|hack|plus)|me[/.]earth[/.]phobos|wexside|wave[-_ ]?client|mio[-_ ]?client|lemon[-_ ]?client|ares[-_ ]?client|entropy[-_ ]?client|celestial[-_ ]?client|akira[-_ ]?client|rinor[-_ ]?client|ozone[-_ ]?client|tarasande|azura[-_ ]?client|drip[-_ ]?client|remix[-_ ]?client|flux[-_ ]?client|wolfram[-_ ]?client|meteor[-_ ]?rejects|trouser[-_ ]?streak|numby[-_ ]?hack|anti[-_ ]?cope|banana[-_ ]?plus|pyro[-_ ]?client|dqrkis|lvstrng|vape\.gg|intent\.store|rise\.today|club[/.]maxstats|wtf[/.]moonlight|me[/.]zeroeightsix|net[/.]ccbluex|today[/.]opai|com[/.]alan[/.]clients|dev[.]gambleclient|xyz[/.]greaj|(?:dev|skid)[/.]krypton|nursultan|expensive[-_ ]?client|excellent[-_ ]?client|minced[-_ ]?client|nixware|raven[-_ ]?xd|nightx[-_ ]?client|jello[-_ ]?client|ghost[-_ ]?client)'

    Modules = '(?i)(kill[-_ ]?aura|crystal[-_ ]?aura|auto[-_ ]?crystal|trigger[-_ ]?bot|aim[-_ ]?(?:assist|bot)|silent[-_ ]?aim|anchor[-_ ]?macro|auto[-_ ]?(?:totem|clicker|pearl|armor|anchor|sword|pot)|no[-_ ]?(?:knockback|fall(?:[-_ ]?damage)?|slow(?:[-_ ]?down)?)(?-i:(?![a-z]))|fly[-_ ]?hack|speed[-_ ]?hack|x[-_ ]?ray[-_ ]?hack|player[-_ ]?esp|chest[-_ ]?(?:esp|steal)|cheststealer|fast[-_ ]?(?:place|break)|scaffold(?!ing)|hitbox(?:es)?[-_ ]?(?:expand|hack)|reach[-_ ]?(?:hack|extend)|velocity[-_ ]?(?:hack|cancel)|bunny[-_ ]?hop|jesus[-_ ]?hack|bed[-_ ]?aura|jitter[-_ ]?click(?:er)?|auto[-_ ]?hit(?-i:(?![a-z]))|hit[-_ ]?select(?-i:(?![a-z]))|(?<![a-z0-9_])w[-_ ]?tap(?![a-z])|auto[-_ ]?(?:double[-_ ]?hand|dtap|neth[-_ ]?pot|tpa|firework|breach|inventory[-_ ]?totem)|stun[-_ ]?slam|(?:mace|spear|elytra)[-_ ]?swap|shield[-_ ]?(?:breaker|disabler)|axe[-_ ]?spam|web[-_ ]?macro|key[-_ ]?pearl|(?:hover|legit)[-_ ]?totem|ping[-_ ]?spoof|anti[-_ ]?miss[-_ ]?click|lag[-_ ]?reach|pop[-_ ]?switch|sprint[-_ ]?reset|fake[-_ ]?inv(?![a-z])|pack[-_ ]?spoof|(?<![a-z])(?:double|safe|air)[-_ ]?anchor|anchor[-_ ]?aura|loot[-_ ]?yeeter|walsk?y[-_ ]?(?:crystal[-_ ]?)?optimizer|grim[-_ ]?(?:velocity|disabler)|target[-_ ]?strafe|(?:boat|packet)[-_ ]?fly|(?:player|entity|storage|block|ore|item|mob)[-_ ]?esp(?-i:(?![a-z]))|cave[-_ ]?finder|tp[-_ ]?aura|attack[-_ ]?aura|click[-_ ]?aura|multi[-_ ]?aura|mace[-_ ]?(?:aura|killer|spam)|no[-_ ]?jump[-_ ]?delay|anti[-_ ]?web|fake[-_ ]?lag|lag[-_ ]?switch|timer[-_ ]?hack|packet[-_ ]?(?:cancel|delay)(?-i:(?![a-z]))|inv(?:entory)?[-_ ]?(?:cleaner|stealer)|auto[-_ ]?miner|legit[-_ ]?(?:crystal|anchor)|hit[-_ ]?crystal|(?:rotation|packet)[-_ ]?spoof|auto[-_ ]?(?:crit|weapon|trap|web|offhand)|silent[-_ ]?swap|packet[-_ ]?fly|elytra[-_ ]?fly|safe[-_ ]?walk|hole[-_ ]?filler|self[-_ ]?trap|back[-_ ]?track|criticals|auto[-_ ]?surround|fast[-_ ]?(?:use|bow)|no[-_ ]?rotate|(?:speed|packet)[-_ ]?mine)'

    ModulesWeakLeaf = '(?i)^(esp|xray|fullbright|nametags|fly|speed|reach|velocity|criticals|antiknockback|autosprint|step|phase|blink|nofall|freecam|tracers|nuker|timer|sneak|spider|jesus|longjump|highjump|airjump|waterwalk|strafe|bhop|safewalk|antikb|hitboxes|aimassist|killaura|triggerbot|autoclicker|scaffold|noslow|nofalldamage|autototem|autoarmor|autopot|autopearl|clicker|aimbot|antibot|autoblock|fastplace|fastbreak|reachhack|autocrystal|crystalaura|bedaura|anchoraura|autoanchor|noknockback|autodtap|wtap|hitselect|stunslam|maceaura|autoweb|antiweb|invcleaner|chestesp|playeresp|autominer|tpaura|clickaura|attackaura|multiaura)(module|hack|mod)?$'
    Bypass  = '(?i)(grim[-_]?bypass|vulcan[-_]?bypass|watchdog[-_]?bypass|matrix[-_]?bypass|nocheat[-_]?bypass|anticheat[-_]?bypass|hypixel[-_]?bypass|spartan[-_]?bypass|verus[-_]?bypass|intave[-_]?bypass)'

    Markers = '(?i)(org[/.]chainlibs|LicenseCheckMixin|phantom-refmap|cheat-refmap|client-refmap|aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA|api\.novaclient\.lol|dqrkis\.xyz)'

    Libs    = '(?i)(jnativehook|imgui[./]binding|imgui[./]glfw)'

    Labels  = '(?i)(place chance|break chance|stop on kill|explode delay|explode chance|glowstone delay|glowstone chance|activates above|click simulation|silent rotations|anchor macro|totem slot|strict one-tick|mace priority|horizontal aim speed|vertical aim speed|no count glitch|only charge|require hold axe|min totems|min pearls|totem first|drop interval|stay open for|predict crystals|particle chance)'

    LabelsWeak = '(?i)(target players|target mobs|target animals|target invisible|ignore friends|ignore teammates|ignore team|min cps|max cps|click delay|hit delay|attack delay|reach distance|attack range|rotation speed|aim smoothing|fov check|through walls|require weapon|only critical|crit mode|swap delay|trigger delay|totem delay|pearl delay|anchor delay|crystal delay|place delay|break delay|auto switch|silent swap|humanize|jitter range)'

    Obfuscators = '(?i)(ALLATORI|(?<![a-z])ZKM[0-9A-Za-z]*|Zelix|Stringer(?:Java)?Obfuscator|com[/.]licel|paramorphism|skidfuscator|itzsomebody|branchlock|com[/.]preemptive|caesium|binscure|(?<![a-z])jnic(?![a-z])|qprotect|superblaze|bozar[-_.]?(?:obf|crypt)[a-z]*|superblaubeere|scuti[-_.]?obf|smoke[-_.]?obf)'

    Malware = @(
        @{ Rule='Discord webhook';          Sev='high';   Rx='(?i)discord(app)?\.com/api/webhooks/' }
        @{ Rule='Telegram bot API';         Sev='high';   Rx='(?i)api\.telegram\.org/bot' }
        @{ Rule='Browser credential DB';    Sev='high';   Rx='(?i)(Login Data|Web Data|Local State|Cookies)[\s\S]{0,200}(Chrome|Edge|Brave|User Data)|User Data[\\/]Default' }
        @{ Rule='Windows DPAPI unwrap';     Sev='high';   Rx='(?i)cryptUnprotectData|Crypt32Util' }
        @{ Rule='Discord token storage';    Sev='high';   Rx='(?i)discord(canary|ptb)?[\\/]+Local Storage|leveldb[\s\S]{0,120}(\.ldb|\.log)|dQw4w9WgXcQ:' }
        @{ Rule='Minecraft session theft';  Sev='high';   Rx='(?i)launcher_accounts\.json|launcher_profiles\.json[\s\S]{0,200}(accessToken|clientToken)|accessToken[\s\S]{0,100}getSession' }
        @{ Rule='Steam/Telegram session theft'; Sev='high'; Rx='(?i)loginusers\.vdf|ssfn[0-9]{6,}|Telegram[\\/]+tdata' }
        @{ Rule='Crypto miner';             Sev='high';   Rx='(?i)xmrig|stratum\+(tcp|ssl)://|randomx|cryptonight|monero' }
        @{ Rule='Crypto wallet theft';      Sev='high';   Rx='(?i)(Exodus|Atomic|Electrum|MetaMask|wallet\.dat)[\s\S]{0,150}(Roaming|AppData|\.minecraft)' }
        @{ Rule='PowerShell launch';        Sev='high';   Rx='(?i)powershell(\.exe)?[\s\S]{0,60}(-enc|-w\s+hidden|-windowstyle|downloadstring|iex)' }
        @{ Rule='Antivirus tampering';      Sev='high';   Rx='(?i)Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath' }
        @{ Rule='Dropper (exe/dll/bat)';    Sev='medium'; Rx='(?i)(\.exe|\.dll|\.bat|\.vbs|\.ps1)[\s\S]{0,40}(openStream|openConnection|Files\.copy|FileOutputStream)' }
        @{ Rule='Run dropped file';         Sev='medium'; Rx='(?i)rundll32|cmd(\.exe)?["'' ,]+/c' }
        @{ Rule='Startup persistence';      Sev='high';   Rx='(?i)CurrentVersion[\\/]+Run|Start Menu[\\/]+Programs[\\/]+Startup|schtasks' }
        @{ Rule='fractureiser IOC';         Sev='high';   Rx='(?i)85\.217\.144\.130|dev[/.]neko[/.]nekoclient|libWebGL64|\.ref\b[\s\S]{0,20}lib\.jar' }
        @{ Rule='Keylogger / screen grab';  Sev='high';   Rx='(?i)SetWindowsHookEx|GetAsyncKeyState|keylog|java[./]awt[./]Robot[\s\S]{0,80}createScreenCapture' }
        @{ Rule='Reverse shell';            Sev='high';   Rx='(?i)reverse[-_ ]?shell' }
        @{ Rule='Token / session grabber';  Sev='high';   Rx='(?i)session[-_]?stealer|token[-_]?(?:logger|grabber)' }
        @{ Rule='Analysis-tool detection';  Sev='medium'; Rx='(?i)x64dbg|wireshark|processhacker|ollydbg|cheat ?engine' }
        @{ Rule='VM / sandbox detection';   Sev='low';    Rx='(?i)vboxservice|sandboxie|vmtoolsd' }
        @{ Rule='IP lookup / exfil';        Sev='medium'; Rx='(?i)api\.ipify\.org|ip-api\.com|checkip\.amazonaws\.com|ipinfo\.io' }
        @{ Rule='On-chain C2 (blockchain RPC)'; Sev='medium'; Rx='(?i)eth_call|bsc-dataseed|infura\.io|polygon-rpc|rpc\.ankr\.com' }
        @{ Rule='Java agent / boot-classpath hook'; Sev='medium'; Rx='(?i)Premain-Class|Launcher-Agent-Class|Agent-Class|Can-Retransform-Classes|Boot-Class-Path' }
        @{ Rule='Manifest loads an external jar'; Sev='medium'; Rx='(?i)Class-Path:\s*(https?:|[A-Za-z]:[\\/]|/)' }
        @{ Rule='Legacy tweaker / core plugin (runs before the game)'; Sev='low'; Rx='(?i)(FMLCorePlugin|TweakClass)\s*:\s*\S+' }
    )

    FakeIds = @('sodium','lithium','iris','fabric-api','fabric','modmenu','optifine','starlight','phosphor','ferritecore','entityculling','indium','lazydfu','krypton','memoryleakfix','c2me-fabric','smoothboot-fabric','immediatelyfast','noisium','threadtweak')
}
$Rx = @{}
foreach ($k in 'Clients', 'Modules', 'ModulesWeakLeaf', 'Bypass', 'Markers', 'Libs', 'Obfuscators', 'Labels', 'LabelsWeak') { $Rx[$k] = New-Object Regex($Sig[$k], 'Compiled') }
$MalwareRx = foreach ($m in $Sig.Malware) { [pscustomobject]@{ Rule = $m.Rule; Sev = $m.Sev; Rx = (New-Object Regex($m.Rx, 'Compiled')) } }

$BannedMods = [ordered]@{
    'autoclicker' = 'Auto Clicker'
    'autoclickermod' = 'Auto Clicker'
    'clickcrystals' = 'Click Crystals'
    'doublekeybinds' = 'Double Key Binds'
    'multikeybindings' = 'Multi Key Bindings'
    'fastplace' = 'Fast Place'
    'fastrightclick' = 'Fast Right Click'
    'rightclickmod' = 'RightClickMod'
    'nodelayoptimizer' = 'No Delay Optimizer'
    'noinputlagtickrate' = 'No Input Lag Tick Rate'
    'quickhotkeys' = 'Quick Hotkeys'
    'quickmath' = 'Quickmath'
    'quickmth' = 'Quickmath'
    'consumableoptimizers' = 'Consumable Optimizers'
    'consumableoptimizer' = 'Consumable Optimizers'
    'bridgingmod' = 'Bridging Mod'
    'bridging' = 'Bridging Mod'
    'g1axcrystaloptimizer' = 'G1ax Crystal Optimizer'
    'walksycrystaloptimizer' = 'Walksy Crystal Optimizer'
    'kindscrystaloptimizer' = 'Kind''s Crystal Optimizer'
    'hazelcrystaloptimizer' = 'Hazel Crystal Optimizer'
    'maceoptimiser' = 'Mace Optimiser'
    'maceoptimizer' = 'Mace Optimiser'
    'maceattackassistance' = 'Mace Attack Assistance'
    'bettermaceswap' = 'Better Mace Swap'
    'fasttotem' = 'Fast Totem'
    'switchtotems' = 'SwitchTotems'
    'autototem' = 'Auto Totem'
    'autocrystal' = 'Auto Crystal'
    'armorhotswap' = 'Armor Hotswap'
    'arrowshifter' = 'Arrow Shifter'
    'autoswitch' = 'Autoswitch'
    'dhandmod' = 'D-hand Mod'
    'dhand' = 'D-hand Mod'
    'dokkoshotbaroptimizer' = 'Dokko''s Hotbar Optimizer'
    'dokkos' = 'Dokko''s Hotbar Optimizer'
    'doublehotbar' = 'Double Hotbar'
    'xaerobetterpvp' = 'Xaero Better PvP'
    'betterpvp' = 'Xaero Better PvP'
    'fastxp' = 'Fast XP'
    'quickxp' = 'Quick XP'
    'quickexp' = 'Quick XP'
    'quickelytra' = 'Quick Elytra'
    'autoelytra' = 'Auto Elytra'
    'killaura' = 'Killaura'
    'aimbotaimassist' = 'Aimbot / Aim Assist'
    'aimbot' = 'Aimbot / Aim Assist'
    'aimassist' = 'Aimbot / Aim Assist'
    'triggerbot' = 'Triggerbot'
    'nofall' = 'NoFall'
    'xrayanyxraymod' = 'Xray (any X-ray mod)'
    'xray' = 'Xray (any X-ray mod)'
    'xrayultimate' = 'Xray (any X-ray mod)'
    'advancedxray' = 'Xray (any X-ray mod)'
    'simplexray' = 'Xray (any X-ray mod)'
    'fabricxray' = 'Xray (any X-ray mod)'
    'xraymod' = 'Xray (any X-ray mod)'
    'cheststorageplayeresp' = 'Chest / Storage / Player ESP'
    'chestesp' = 'Chest / Storage / Player ESP'
    'storageesp' = 'Chest / Storage / Player ESP'
    'playeresp' = 'Chest / Storage / Player ESP'
    'entityesp' = 'Chest / Storage / Player ESP'
    'litematicaprinter' = 'Litematica Printer'
    'wurst' = 'Wurst'
    'wurstclient' = 'Wurst'
    'meteorclient' = 'Meteor Client'
    'aristois' = 'Aristois'
    'liquidbounce' = 'LiquidBounce'
    'futureclient' = 'Future Client'
    'rusherhack' = 'RusherHack'
    'thunderhack' = 'ThunderHack'
    'vapev4lite' = 'Vape (V4 / Lite)'
    'vapev4' = 'Vape (V4 / Lite)'
    'vapelite' = 'Vape (V4 / Lite)'
    'vapeclient' = 'Vape (V4 / Lite)'
    'ravenb' = 'Raven B+'
    'ravenbplus' = 'Raven B+'
    'sigmaclient' = 'Sigma Client'
    'novoline' = 'Novoline'
    'astolfo' = 'Astolfo'
    'tenacity' = 'Tenacity'
    'tenacityclient' = 'Tenacity'
    'riseclient' = 'Rise Client'
    'slinky' = 'Slinky'
    'slinkyclient' = 'Slinky'
    'pandaware' = 'Pandaware'
    'bleachhack' = 'BleachHack'
    'salhack' = 'Salhack'
    'konas' = 'Konas'
    'konasclient' = 'Konas'
    'phobos' = 'Phobos'
    'phobosclient' = 'Phobos'
    '3arthh4ck' = '3arthh4ck'
    'kamiblue' = 'Kami Blue'
    'forgehax' = 'ForgeHax'
    'inertia' = 'Inertia'
    'inertiaclient' = 'Inertia'
    'exhibition' = 'Exhibition'
    'exhibitionclient' = 'Exhibition'
    'doomsday' = 'Doomsday'
    'doomsdayclient' = 'Doomsday'
    'prestige' = 'Prestige'
    'prestigeclient' = 'Prestige'
    'fdpclient' = 'FDPClient'
    'trollhack' = 'Trollhack'
    'boze' = 'Boze'
    'bozeclient' = 'Boze'
    'impactclient' = 'Impact Client'
    'hanabi' = 'Hanabi'
    'hanabiclient' = 'Hanabi'
    'xulu' = 'Xulu'
    'xuluclient' = 'Xulu'
    'lunarcheatcosmos' = 'Lunar Cheat / Cosmos'
    'lunarcheat' = 'Lunar Cheat / Cosmos'
    'cosmosclient' = 'Lunar Cheat / Cosmos'
    'baritone' = 'Baritone'
    'meteorbaritone' = 'Baritone'
    'altoclef' = 'Altoclef'
    'automatone' = 'Automatone'
    'jsmacros' = 'JsMacros'
    'minescript' = 'Minescript'
    'macromod' = 'Macro Mod'
    'macrokeybinds' = 'Macro Mod'
    'safewalk' = 'SafeWalk'
    'noknockback' = 'No Knockback'
    'antiknockback' = 'No Knockback'
    'reachmod' = 'Reach Mod'
    'reachextender' = 'Reach Mod'
    'extendedreach' = 'Reach Mod'
    'hitboxexpander' = 'Hitbox Expander'
    'hitboxmod' = 'Hitbox Expander'
    'fastbridge' = 'Fast Bridge'
    'godbridge' = 'Fast Bridge'
    'scaffoldmod' = 'Scaffold'
    'tracersmod' = 'Tracers'
    'orehighlighter' = 'Ore Highlighter'
    'orefinder' = 'Ore Finder'
    'lagswitch' = 'Lag Switch'
    'fakelag' = 'Fake Lag'
    'bedrockminer' = 'Bedrock Miner'
    'noclip' = 'NoClip'
    'fastbreak' = 'Fast Break'
    'glowesp' = 'Glow ESP'
    'seedmapper' = 'SeedMapper'
    'flyhack' = 'Fly Hack'
    'speedhack' = 'Speed Hack'
    'autoblock' = 'Auto Block'
    'autoarmor' = 'Auto Armor'
    'criticals' = 'Criticals'
    'nokb' = 'No Knockback'
    'catlean' = 'Catlean Client'
    'catleanclient' = 'Catlean Client'
    'argonclient' = 'Argon Client'
    'gypsyclient' = 'Gypsy Client'
    'virginclient' = 'Virgin Client'
    'grimclient' = 'Grim Client'
    'novaclient' = 'Nova Client'
    'hellionclient' = 'Hellion Client'
    'hellion' = 'Hellion Client'
    'autodoublehand' = 'Auto Double Hand'
    'autodtap' = 'Auto Dtap'
    'autonethpot' = 'Auto Neth Pot'
    'autopotrefill' = 'Auto Pot Refill'
    'stunslam' = 'Stun Slam'
    'maceswap' = 'Mace Swap'
    'keypearl' = 'Key Pearl'
    'webmacro' = 'Web Macro'
    'shielddisabler' = 'Shield Disabler'
    'shieldbreaker' = 'Shield Breaker'
    'hovertotem' = 'Hover Totem'
    'legittotem' = 'Legit Totem'
    'autoinventorytotem' = 'Auto Inventory Totem'
    'pingspoof' = 'Ping Spoof'
    'walksyoptimizer' = 'Walksy Optimizer'
}
$SuspectMods = [ordered]@{
    'litematica' = 'Litematica'
    'minihud' = 'MiniHUD'
    'tweakeroo' = 'Tweakeroo'
    'tweakermore' = 'Tweakermore'
    'itemscroller' = 'Item Scroller'
    'syncmatica' = 'Syncmatica'
    'axiom' = 'Axiom'
    'worldeditcui' = 'WorldEdit CUI'
    'schematica' = 'Schematica'
    'accurateblockplacement' = 'Accurate Block Placement'
    'floursvarioustweaks' = 'Flour''s Various Tweaks'
    'fluidlogged' = 'Fluidlogged'
    'easyplace' = 'Easy Place'
    'camerautils' = 'Camera Utils'
    'betterthirdperson' = 'Better Third Person'
    'shouldersurfingreloaded' = 'Shoulder Surfing Reloaded'
    'shouldersurfing' = 'Shoulder Surfing Reloaded'
    'perspectivemodredux' = 'Perspective Mod Redux'
    'perspective' = 'Perspective Mod Redux'
    'freelook' = 'Freelook'
    'replaymod' = 'Replay Mod'
    'flashback' = 'Flashback'
    'shieldinfo' = 'Shield Info'
    'shieldstatus' = 'Shield Status'
    'shieldindicator' = 'Shield Indicator'
    'armorstatus' = 'Armor Status'
    'armorhud' = 'Armor HUD'
    'totemcounter' = 'Totem Counter'
    'crystalcounter' = 'Crystal Counter'
    'damageindicators' = 'Damage Indicators'
    'damageindicator' = 'Damage Indicators'
    'hitindicator' = 'Hit Indicator'
    'healthindicators' = 'Health Indicators'
    'healthindicator' = 'Health Indicators'
    'neat' = 'Neat'
    'cpscounter' = 'CPS Counter'
    'cpsdisplay' = 'CPS Counter'
    'keystrokes' = 'Keystrokes'
    'bettercombat' = 'Better Combat'
    'journeymap' = 'JourneyMap'
    'voxelmap' = 'VoxelMap'
    'inventoryprofilesnext' = 'Inventory Profiles Next'
    'inventorymanagement' = 'Inventory Management'
    'inventorycontroltweaks' = 'Inventory Control Tweaks'
    'inventorysorting' = 'Inventory Sorting'
    'inventorytweaks' = 'Inventory Tweaks'
    'mousetweaks' = 'Mouse Tweaks'
    'mousewheelie' = 'Mouse Wheelie'
    'sort' = 'Sort'
    'quickcraft' = 'Quickcraft'
    'slotcycler' = 'Slot Cycler'
    'frostbytesimprovedinventory' = 'Frostbyte''s Improved Inventory'
    'invmove' = 'InvMove'
    'betterscreens' = 'Better Screens'
    'nightvision' = 'Night Vision'
    'lightoverlay' = 'Light Overlay'
    'viafabric' = 'ViaFabric'
    'viafabricplus' = 'ViaFabricPlus'
    'viaforge' = 'ViaForge'
    'geyser' = 'Geyser'
    'bedrockify' = 'Bedrockify'
    'vivecraftvr' = 'Vivecraft (VR)'
    'vivecraft' = 'Vivecraft (VR)'
    'pingequalizer' = 'Ping Equalizer'
    'omniscience' = 'Omniscience'
    'autofish' = 'Auto Fish'
    'togglesneak' = 'Toggle Sneak'
    'autosprint' = 'Auto Sprint'
    'autowalk' = 'Auto Walk'
    'reachdisplay' = 'Reach Display'
    'reachcircle' = 'Reach Circle'
    'chesttracker' = 'Chest Tracker'
    'whereisit' = 'Where Is It'
    'inventorysorter' = 'Inventory Sorter'
    'inventoryhudplus' = 'Inventory HUD+'
    'autoeat' = 'Auto Eat'
    'autotool' = 'Auto Tool'
    'hotbarswapper' = 'Hotbar Swapper'
    'amecs' = 'Amecs'
    'amecsreborn' = 'Amecs Reborn'
    'elytraautoflight' = 'Elytra Auto Flight'
    'entityradar' = 'Entity Radar'
    'radar' = 'Radar'
    'worldedit' = 'WorldEdit'
    'pvphud' = 'PvP HUD'
    'combathud' = 'Combat HUD'
    'targethud' = 'Target HUD'
    'enemyhealthbar' = 'Enemy Health Bar'
    'healthbars' = 'Health Bars'
    'itemcounter' = 'Item Counter'
    'cooldownindicator' = 'Cooldown Indicator'
    'attackindicator' = 'Attack Indicator'
    'minimap' = 'Minimap'
    'betterminimap' = 'Minimap'
    'antiquemap' = 'Minimap'
    'xaeroplus' = 'XaeroPlus'
    'nofog' = 'No Fog'
    'nightvisionmod' = 'Night Vision'
    'brightness' = 'Brightness Mod'
    'superbright' = 'Super Bright'
    'itemswapper' = 'Item Swapper'
    'swapmod' = 'Swap Mod'
    'hotbarcycle' = 'Hotbar Cycle'
    'autohotbar' = 'Auto Hotbar'
    'autorefill' = 'Auto Refill'
    'autorestock' = 'Auto Restock'
    'quicksort' = 'Quick Sort'
    'containersort' = 'Container Sort'
    'itemsorting' = 'Item Sorting'
    'betterblockplacement' = 'Better Block Placement'
    'blockplacement' = 'Block Placement Tweaks'
    'placementpreview' = 'Placement Preview'
    'airplace' = 'Air Place'
    'scaffoldingplace' = 'Scaffolding Place'
    'bridgehelper' = 'Bridge Helper'
    'bridgeassist' = 'Bridge Assist'
    'sprintmod' = 'Sprint Mod'
    'sneakmod' = 'Sneak Mod'
    'autojump' = 'Auto Jump'
    'stepassist' = 'Step Assist'
    'keybindmanager' = 'Keybind Manager'
    'extrakeybinds' = 'Extra Keybinds'
    'modifierkeys' = 'Modifier Keybinds'
}
$BannedModKeys  = @($BannedMods.Keys  | Sort-Object Length -Descending)
$SuspectModKeys = @($SuspectMods.Keys | Sort-Object Length -Descending)

function ConvertTo-ModKey([string]$Text) {
    if (-not $Text) { return '' }
    return ($Text.ToLowerInvariant() -replace '[^a-z0-9]', '')
}

function Find-PolicyKey($Table, $SortedKeys, [string[]]$Keys) {
    foreach ($key in $Keys) {
        if ($Table.Contains($key)) { return [string]$Table[$key] }
    }
    foreach ($key in $Keys) {
        if ($key.Length -ge 6) {
            foreach ($name in $SortedKeys) {
                if ($name.Length -ge 6 -and $key.StartsWith($name, [StringComparison]::Ordinal)) { return [string]$Table[$name] }
            }
        }
    }
    return $null
}

function Get-PolicyMod($Meta, [string]$FileName, [string]$ModrinthTitle) {
    $keys = New-Object System.Collections.Generic.List[string]
    $cands = New-Object System.Collections.Generic.List[string]
    if ($ModrinthTitle) { $cands.Add([string]$ModrinthTitle) }
    if ($Meta) {
        if ($Meta.Id) { $cands.Add([string]$Meta.Id) }
        if ($Meta.Name) { $cands.Add([string]$Meta.Name) }
    }
    if ($FileName) {
        $base = $FileName -replace '(?i)\.(disabled|old|bak|duplicate|backup|off)$', ''
        $base = [IO.Path]::GetFileNameWithoutExtension($base)
        if ($base) { $cands.Add($base) }
    }
    foreach ($candidate in $cands) { $k = ConvertTo-ModKey $candidate; if ($k) { $keys.Add($k) } }
    if ($keys.Count -eq 0) { return $null }
    $keyArr = $keys.ToArray()
    $hit = Find-PolicyKey $BannedMods $BannedModKeys $keyArr
    if ($hit) { return [pscustomobject]@{ Kind = 'banned'; Name = $hit } }
    $hit = Find-PolicyKey $SuspectMods $SuspectModKeys $keyArr
    if ($hit) { return [pscustomobject]@{ Kind = 'suspect'; Name = $hit } }
    return $null
}

$LegitMods = [ordered]@{
    'axiom' = 'Axiom'
    'worldedit' = 'WorldEdit'
    'worldeditmod' = 'WorldEdit'
    'worldeditcui' = 'WorldEdit CUI'
    'worldeditcuifabric' = 'WorldEdit CUI'
    'fastasyncworldedit' = 'FastAsyncWorldEdit'
    'effortlessbuilding' = 'Effortless Building'
    'litematica' = 'Litematica'
    'syncmatica' = 'Syncmatica'
    'schematica' = 'Schematica'
    'minihud' = 'MiniHUD'
    'flashback' = 'Flashback'
    'replaymod' = 'Replay Mod'
    'reachdisplay' = 'Reach Display'
    'reachdisplaymod' = 'Reach Display'
}

function Get-LegitMod($Meta, [string]$FileName, [string]$ModrinthTitle) {
    $cands = New-Object System.Collections.Generic.List[string]
    if ($ModrinthTitle) { $cands.Add([string]$ModrinthTitle) }
    if ($Meta) {
        if ($Meta.Id) { $cands.Add([string]$Meta.Id) }
        if ($Meta.Name) { $cands.Add([string]$Meta.Name) }
    }
    if ($FileName) {
        $base = [IO.Path]::GetFileNameWithoutExtension(($FileName -replace '(?i)\.(disabled|old|bak|duplicate|backup|off)$', ''))
        $stem = [regex]::Replace($base, '(?i)[-_ +]*(mc|fabric|forge|neoforge|quilt|v)?[-_ +]*\d.*$', '')
        if ($stem) { $cands.Add($stem) }
    }
    foreach ($c in $cands) {
        $k = ConvertTo-ModKey $c
        if ($k -and $LegitMods.Contains($k)) { return [string]$LegitMods[$k] }
    }
    return $null
}

$Latin1 = [Text.Encoding]::GetEncoding(28591)

$FullwidthRx = New-Object Regex('(?:\u00EF[\u00BC\u00BD][\u0080-\u00BF]){3,}', 'Compiled')

$DllInjectRx = New-Object Regex('(?i)\b(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|NtCreateThreadEx|QueueUserAPC|SetThreadContext|NtWriteVirtualMemory|RtlCreateUserThread)\b', 'Compiled')
$DllInputRx  = New-Object Regex('(?i)\b(SendInput|mouse_event|keybd_event|SetWindowsHookEx[AW]?|GetAsyncKeyState|GetKeyboardState|RegisterRawInputDevices)\b', 'Compiled')
$DllStealRx  = New-Object Regex('(?i)\b(CryptUnprotectData|URLDownloadToFile[AW]?|InternetOpen[AW]?|WinHttpOpen)\b', 'Compiled')

$ToolDefs = @(
    @{ Cat='injector';   Sev='high';   Rule='Injector / manual-mapper';                   Rx='(?i)(extreme ?injector|xenos(64|32)?\.exe|xenos injector|gh ?injector|remoteinjector|kdmapper|(?<![a-z])kdu\.exe|processinjector|dll ?injector|winject|injector\.exe|manualmap)' }
    @{ Cat='memedit';    Sev='high';   Rule='Memory editor (Cheat Engine & similar)';    Rx='(?i)(cheat ?engine|cheatengine|(?<![a-z])dbk(32|64)|artmoney|tsearch)' }
    @{ Cat='clicker';    Sev='high';   Rule='Auto-clicker';                               Rx='(?i)(auto ?clicker|autoclicker|op ?auto ?clicker|gs ?auto ?clicker|murgee|jitter ?click|free ?clicker|rapid ?clicker|fast ?clicker|cps ?(bot|booster))' }
    @{ Cat='adapter';    Sev='high';   Rule='Console cheat adapter software (Cronus/XIM...)'; Rx='(?i)(cronus|zen ?studio|xim ?(apex|matrix|nexus|manager)|strike ?pack|titan ?two|reasnow|brook ?(wingman|fighting))' }
    @{ Cat='macro';      Sev='medium'; Rule='Macro / automation tool';                    Rx='(?i)(autohotkey|autoit3|autoit|tinytask|macro ?recorder|jitbit|pulover|x-?mouse ?button|198macros|dqrkis|(?<![a-z])ahk(?![a-z]))' }
    @{ Cat='peripheral'; Sev='low';    Rule='Macro-capable peripheral software';          Rx='(?i)(bloody ?7|bloody ?software|a4tech|razer ?synapse|logitech ?g ?hub|lghub|steelseries ?(gg|engine)|corsair ?icue)' }
    @{ Cat='debugger';   Sev='medium'; Rule='Debugger / reverse-engineering tool';        Rx='(?i)(x(32|64)dbg|ollydbg|windbg|(?<![a-z])ida(64)?\.exe|ghidra|dnspy|reclass|scylla|process ?hacker|processhacker|systeminformer|api ?monitor|bytecode-?viewer|recaf|jd-gui|cff ?explorer|hxd(64)?\.exe|detect ?it ?easy|(?<![a-z])de4dot)' }
    @{ Cat='sniffer';    Sev='low';    Rule='Network sniffer / proxy tool';               Rx='(?i)(wireshark|fiddler|burp ?suite|mitmproxy|charles ?proxy)' }
    @{ Cat='remote';     Sev='low';    Rule='Remote desktop / assistance tool';          Rx='(?i)(anydesk|teamviewer|rustdesk|parsecd?\.exe|remoting_host|chrome ?remote ?desktop|ultraviewer|splashtop|logmein|tightvnc|ultravnc|winvnc|tvnserver|vncviewer|realvnc|radmin|nomachine|supremo|ammyy|screenconnect|rcservice|dwservice|rdpwrap|quickassist|(?<![a-z])msra\.exe|ngrok|sunshine\.exe|moonlight|steamlink|dameware|zoho ?assist|remotepc|aeroadmin|getscreen|meshagent)' }
    @{ Cat='vm';         Sev='medium'; Rule='Virtual machine / emulator';                 Rx='(?i)(vmware-vmx|vmplayer|vmware ?workstation|virtualboxvm|vboxsvc|qemu-system|vmwp\.exe|sandboxie|bluestacks|noxplayer|ldplayer)' }
    @{ Cat='wiper';      Sev='high';   Rule='Anti-forensics / wiping tool';               Rx='(?i)(sdelete|bleachbit|ccleaner|privazer|eraser\.exe|usboblivion|usbdeview|killdisk|(?<![a-z])dban|timestomp)' }
)
$ToolSigs = foreach ($t in $ToolDefs) { [pscustomobject]@{ Cat = $t.Cat; Sev = $t.Sev; Rule = $t.Rule; Rx = (New-Object Regex($t.Rx, 'Compiled')) } }
function Get-ToolHit([string]$Text) {
    foreach ($t in $ToolSigs) { if ($t.Rx.IsMatch($Text)) { return $t } }
    return $null
}

$ClientDirRx = New-Object Regex('(?i)^\.?(meteor-client|wurst|liquidbounce|rusherhack|thunderhack|futureclient|future|impact|aristois|vape|vapelite|vapev4|raven|sigma|novoline|astolfo|tenacity|rise|slinky|moonlight|pandaware|asteria|xenon|doomsday|prestige|konas|phobos|salhack|bleachhack|coffee|nodus|kamiblue|forgehax|3arthh4ck|fdpclient|exhibition|zeroday|opai|augustus|198macros)(-?client)?(\d.*)?$', 'Compiled')

$DnsCheatRx  = New-Object Regex('(?i)(vape\.gg|wurstclient|wurst-client|liquidbounce|meteorclient|meteor-client|rusherhack|thunderhack|futureclient|impactclient|aristois|pandaware|doomsday|prestigeclient|198macros|dqrkis|cheatengine|opautoclicker|autoclicker|salhack|bleachhack|konasclient|astolfo|novoline|tenacity-?client|moonlight-?client)', 'Compiled')
$DnsRemoteRx = New-Object Regex('(?i)(anydesk|teamviewer|rustdesk|parsec|splashtop|ultraviewer|logmein|screenconnect|ngrok)', 'Compiled')

$MemClientTerms = @('meteorclient','meteordevelopment','wurstclient','liquidbounce','rusherhack','thunderhack','futureclient','aristois','pandaware','salhack','bleachhack','impactclient','doomsdayclient','raven-b','astolfo','novoline','chainlibs','phantom-refmap','LicenseCheckMixin')
$MemModuleTerms = @('killaura','crystalaura','triggerbot','autoclicker','aimassist','silentaim','cheststealer','anchormacro','autototem','autocrystal','jitterclick','bedaura')

$CmdDefs = @(
    @{ Sev='high';   Rule='Clears event logs';                 Rx='(?i)wevtutil(\.exe)?\s+(cl|clear-log)\b|Clear-EventLog|Remove-EventLog|Limit-EventLog' }
    @{ Sev='high';   Rule='Deletes the USN change journal';    Rx='(?i)fsutil(\.exe)?\s+usn\s+deletejournal' }
    @{ Sev='high';   Rule='Deletes Prefetch / Recent traces';  Rx='(?i)(del|erase|rm|remove-item|rd|rmdir)\b[^|;&]*(prefetch|\\recent\b|automaticdestinations|customdestinations|\.pf\b)' }
    @{ Sev='high';   Rule='Wipes shell history';               Rx='(?i)Clear-History|Remove-Item[^|;&]*ConsoleHost_history|Set-PSReadLineOption\s+-HistorySaveStyle\s+SaveNothing|doskey\s+/reinstall' }
    @{ Sev='high';   Rule='Tampers with Windows Defender';     Rx='(?i)\b(Set-MpPreference\s+-[A-Za-z]*(DisableRealtime|Exclusion)|Add-MpPreference\s+-[A-Za-z]*Exclusion|sc(?:\.exe)?\s+(?:stop|config)\s+WinDefend|reg(?:\.exe)?\s+add\s+.*DisableAntiSpyware)' }
    @{ Sev='high';   Rule='Edits file timestamps';             Rx='(?i)\.(CreationTime|LastWriteTime|LastAccessTime)\s*=|timestomp|SetFileTime|NewFileTimestamp' }
    @{ Sev='high';   Rule='Disables Prefetch / SysMain';       Rx='(?i)EnablePrefetcher|Stop-Service[^|;&]*SysMain|sc(\.exe)?\s+(stop|config)\s+SysMain' }
    @{ Sev='medium'; Rule='Clears the Recycle Bin';            Rx='(?i)Clear-RecycleBin|rd\s+/s\s+/q\s+\S*recycle' }
    @{ Sev='medium'; Rule='Deletes shadow copies';             Rx='(?i)vssadmin(\.exe)?\s+delete|wmic\s+shadowcopy\s+delete' }
    @{ Sev='medium'; Rule='Deletes or renames mod files';      Rx='(?i)(remove-item|del|erase|rm|move|mv|ren|rename-item|move-item)\b[^|;&]*(\.jar\b|[\\/]mods\b)' }
    @{ Sev='medium'; Rule='Downloads executable content';      Rx='(?i)(irm|iwr|invoke-webrequest|invoke-restmethod|curl|wget|bitsadmin|certutil\s+-urlcache|start-bitstransfer)\b[^|;&]*(\.jar|\.exe|\.dll|\.zip|discord(app)?\.com|mega\.nz|mediafire|anonfiles|file\.io|catbox|temp\.sh)' }
    @{ Sev='medium'; Rule='Encoded / obfuscated command';      Rx='(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String' }
    @{ Sev='medium'; Rule='Runs AutoHotkey / macro scripts';   Rx='(?i)autohotkey|\.ahk\b' }
    @{ Sev='medium'; Rule='References a cheat client';         Rx=$Sig.Clients }
    @{ Sev='low';    Rule='Hides files';                       Rx='(?i)attrib(\.exe)?\s+\+[hs]' }
    @{ Sev='low';    Rule='Starts the game manually / agent';  Rx='(?i)javaw?(\.exe)?\s+[^|;&]*(-jar|-javaagent)' }
)
$CmdRules = foreach ($c in $CmdDefs) { [pscustomobject]@{ Sev = $c.Sev; Rule = $c.Rule; Rx = (New-Object Regex($c.Rx, 'Compiled')) } }

function Get-Ext([string]$Name) {
    $dot = $Name.LastIndexOf('.'); $slash = $Name.LastIndexOf('/')
    if ($dot -gt $slash -and $dot -ge 0) { return $Name.Substring($dot).ToLower() }
    return ''
}

function Read-EntryBytes($Entry, [int]$MaxBytes = 12MB) {
    if ($Entry.Length -gt $MaxBytes) { return $null }
    $s = $Entry.Open()
    try {
        $ms = New-Object IO.MemoryStream
        $s.CopyTo($ms)
        $arr = $ms.ToArray()
        return ,$arr
    } finally { $s.Dispose() }
}

function Decode-Fullwidth([string]$Run) {

    $bytes = $Latin1.GetBytes($Run)
    $txt = [Text.Encoding]::UTF8.GetString($bytes)
    $sb = New-Object Text.StringBuilder
    foreach ($ch in $txt.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 0xFF01 -and $c -le 0xFF5E) { [void]$sb.Append([char]($c - 0xFEE0)) } else { [void]$sb.Append($ch) }
    }
    $sb.ToString()
}

function Get-FileHashes([string]$Path) {
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
        try {
            $a1 = [Security.Cryptography.SHA1]::Create(); $a256 = [Security.Cryptography.SHA256]::Create(); $a5 = [Security.Cryptography.MD5]::Create()
            $buf = New-Object byte[] 81920
            while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
                [void]$a1.TransformBlock($buf, 0, $n, $null, 0); [void]$a256.TransformBlock($buf, 0, $n, $null, 0); [void]$a5.TransformBlock($buf, 0, $n, $null, 0)
            }
            [void]$a1.TransformFinalBlock($buf, 0, 0); [void]$a256.TransformFinalBlock($buf, 0, 0); [void]$a5.TransformFinalBlock($buf, 0, 0)
            return [pscustomobject]@{
                Sha1 = ([BitConverter]::ToString($a1.Hash).Replace('-', '').ToLower())
                Sha256 = ([BitConverter]::ToString($a256.Hash).Replace('-', '').ToLower())
                Md5 = ([BitConverter]::ToString($a5.Hash).Replace('-', '').ToLower())
            }
        } finally { $fs.Dispose() }
    } catch { return [pscustomobject]@{ Sha1 = $null; Sha256 = $null; Md5 = $null } }
}

function Add-Hack($State, [string]$Name, [string]$Category, [string]$Evidence, [string]$Strength) {
    if (-not $Name) { return }
    $key = ($Name.ToLower() -replace '[^a-z0-9]', '')
    if (-not $key -or $key.Length -lt 2) { return }
    if ($State.Hacks.ContainsKey($key)) { return }
    if ($State.Hacks.Count -ge 80) { return }
    $State.Hacks[$key] = [pscustomobject]@{
        Name = (Limit-Text $Name 60); Category = $Category; Kind = (Get-HackKind $Name $Category)
        Evidence = (Limit-Text $Evidence 160); Strength = $Strength; Keybind = $null; KeybindSource = $null
    }
}

function Test-DllBytes($Bytes, [string]$Where, $Findings) {
    if (-not $Bytes -or $Bytes.Length -lt 64) { return }
    $text = $Latin1.GetString($Bytes)
    $inj = @{}; foreach ($m in $DllInjectRx.Matches($text)) { $inj[$m.Value.ToLower()] = $true }
    $inp = @{}; foreach ($m in $DllInputRx.Matches($text)) { $inp[$m.Value.ToLower()] = $true }
    $stl = @{}; foreach ($m in $DllStealRx.Matches($text)) { $stl[$m.Value.ToLower()] = $true }
    if ($inj.Count -ge 2) { $Findings.Add((New-Finding 'high' 'native' 'DLL imports process-injection APIs' (($inj.Keys | Sort-Object) -join ', ') $Where)) }
    if ($inp.Count -ge 1) { $Findings.Add((New-Finding 'medium' 'native' 'DLL imports input hooking/simulation APIs (autoclicker-style)' (($inp.Keys | Sort-Object) -join ', ') $Where)) }
    if ($stl.ContainsKey('cryptunprotectdata') -and $stl.Count -ge 2) { $Findings.Add((New-Finding 'high' 'native' 'DLL can decrypt Windows credentials and use the network' (($stl.Keys | Sort-Object) -join ', ') $Where)) }
}

$script:NameSev = @{ Clients = 'high'; Markers = 'high'; Bypass = 'high'; Modules = 'medium'; Libs = 'medium'; Obfuscators = 'medium' }
$script:NameCat = @{ Clients = 'cheat-name'; Markers = 'cheat-name'; Bypass = 'cheat-name'; Modules = 'cheat-name'; Libs = 'library'; Obfuscators = 'obfuscation' }

function Scan-HiddenArchive($Entry, [string]$Where, [int]$Depth, $State, $Findings) {
    if ($Depth -ge 3 -or $Entry.Length -gt 40MB) { return }
    $hb = Read-EntryBytes $Entry 40MB
    if (-not $hb) { return }
    try {
        $hz = New-Object IO.Compression.ZipArchive((New-Object IO.MemoryStream(, $hb)), 'Read')
        $hs = Scan-Archive $hz $Where ($Depth + 1) $State
        foreach ($hf in $hs.Findings) { $Findings.Add($hf) }
        [void]$State.Nested.Add([pscustomobject]@{ File = (Limit-Text $Where 100); Classes = [int]$hs.ClassCount; Id = $null })
        $State.NestedJars++
        $hz.Dispose()
    } catch {}
}

function Scan-Archive($Zip, [string]$Label, [int]$Depth, $State) {
    $findings = New-Object System.Collections.Generic.List[object]
    $classNames = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $declared = @{}
    $weak = @{}
    $majors = @{}
    $magicBudget = 3000
    $labelHits = @{}
    $labelWeak = @{}
    $pb = $null
    if ($script:ProfilerOk) { $pb = New-Object CactusHacksDetector.ProfileBuilder }
    $profCount = 0
    $langDone = 0
    $resNames = New-Object System.Collections.Generic.List[string]
    $moduleDirs = @{}
    $moduleCount = 0
    $encClasses = New-Object System.Collections.Generic.List[string]
    $encTotal = 0; $encDec = 0
    $mixCfg = New-Object System.Collections.Generic.List[object]
    $mixDyn = $false
    $libRx = '^(org/objectweb/|org/spongepowered/|net/fabricmc/|net/minecraftforge/|net/neoforged/|cpw/mods/|org/quiltmc/|kotlin/|kotlinx/|org/jetbrains/|org/apache/|com/google/|javassist/|org/codehaus/|org/luaj/|org/graalvm/|org/mozilla/|groovy/|scala/|io/netty/|org/slf4j/|org/yaml/|org/joml/|it/unimi/|com/mojang/|net/minecraft/|me/shedaniel/|dev/architectury/|com/electronwill/|org/h2/|org/sqlite/|com/zaxxer/|com/github/benmanes/|org/bouncycastle/|org/tukaani/|com/fasterxml/)'

    $platform = $false
    $hackKeysBefore = @($State.Hacks.Keys)
    foreach ($pmName in 'fabric.mod.json', 'quilt.mod.json') {
        $pme = $Zip.GetEntry($pmName)
        if ($pme -and -not $platform) {
            $pmb = Read-EntryBytes $pme 1MB
            if ($pmb) {
                $pmt = [Text.Encoding]::UTF8.GetString($pmb)
                if ($pmt -match '"id"\s*:\s*"([^"]+)"') {
                    $pid2 = $Matches[1]
                    if ($pid2 -match '^(fabric-[a-z0-9-]+-v\d+|fabric-api|fabric-api-base|fabric-loader|fabricloader|quilted_fabric_api|qsl|quilt_loader|quilt_[a-z_]+)$') {
                        $platform = $true
                        foreach ($pe in $Zip.Entries) {
                            $pn = $pe.FullName
                            if ($pn.EndsWith('.class') -and -not $pn.StartsWith('META-INF/') -and $pn -notmatch '^(net/fabricmc/|org/quiltmc/)') { $platform = $false; break }
                        }
                    }
                }
            }
        }
    }

    foreach ($metaName in 'fabric.mod.json', 'META-INF/jarjar/metadata.json') {
        $me = $Zip.GetEntry($metaName)
        if ($me) {
            $mb = Read-EntryBytes $me 2MB
            if ($mb) {
                $mt = [Text.Encoding]::UTF8.GetString($mb)
                foreach ($mm in [regex]::Matches($mt, '"(?:file|path)"\s*:\s*"([^"]+)"')) { $declared[$mm.Groups[1].Value.ToLower()] = $true }
            }
        }
    }

    $count = 0
    foreach ($e in $Zip.Entries) {
        $count++
        if ($count -gt 80000) { $findings.Add((New-Finding 'low' 'bypass' 'Archive has an unusually large number of entries (scan truncated)' "$count+" $Label)); break }
        if ($State.BytesScanned -gt 800MB) { $findings.Add((New-Finding 'low' 'bypass' 'Scan budget reached (possible zip bomb), rest not scanned' '' $Label)); break }
        $name = $e.FullName
        if ($name.EndsWith('/')) { continue }
        $where = "$Label!$name"
        $ext = Get-Ext $name
        $isClass = ($ext -eq '.class')
        $leaf = $name.Substring($name.LastIndexOf('/') + 1)
        $base = ($leaf -replace '\.class$', '') -replace '\$.*$', ''

        if ($isClass) {
            $classNames.Add(($name -replace '\.class$', ''))
            if ($name -match '(?i)(^|/)(modules?|hacks?|cheats?)/(?:([^/]+)/)?[^/$]+\.class$') { $moduleCount++; if ($Matches[3]) { $moduleDirs[$Matches[3].ToLower()] = $true } }
        } elseif ($Depth -eq 0 -and $resNames.Count -lt 400 -and $ext -notin '.png', '.ogg', '.jpg', '.jpeg', '.mcmeta', '.wav', '.gif', '.ttf', '.otf', '.nbt', '.bmp', '.fsh', '.vsh', '.glsl') { $resNames.Add($name) }
        foreach ($k in 'Clients', 'Modules', 'Bypass', 'Markers', 'Libs', 'Obfuscators') {
            $m = $Rx[$k].Match($name)
            if ($m.Success) {
                $sk = "$k|$($m.Value.ToLower())"
                if (-not $seen[$sk]) {
                    $seen[$sk] = $true
                    $findings.Add((New-Finding $script:NameSev[$k] $script:NameCat[$k] "$k match" "'$($m.Value)' in path" $where))
                    if ($k -eq 'Modules') { $hn = $m.Value; if ($isClass) { $hn = $base }; Add-Hack $State $hn '' "class/file name: $name" 'name' }
                    if ($k -eq 'Clients') { Add-Hack $State $m.Value 'client' "client name in path: $name" 'client' }
                }
            }
        }
        if ($isClass) {
            if ($Rx.ModulesWeakLeaf.IsMatch($base)) { $weak[$base.ToLower()] = $name }
            if ($name -match '(?i)/modules?/(combat|movement|exploit|ghost|fight|motion|legit)/([^/$]+?)(\$.*)?\.class$') { Add-Hack $State $Matches[2] $Matches[1] "class in modules/$($Matches[1])/" 'class' }
        }
        if (($name -match '(?i)^META-INF/services/(cpw\.mods\.modlauncher\.|net\.minecraftforge\.forgespi\.|net\.neoforged\.neoforgespi\.|net\.neoforged\.fml\.)') -or $name -ieq 'META-INF/coremods.json') {
            if (-not $seen['svc']) { $seen['svc'] = $true; $findings.Add((New-Finding 'low' 'bypass' 'Loader service / coremod entry (code that runs before mods load)' $name $where)) }
        }
        if ($name -match '(?i)(^|/)(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.[^/]*)?(/|$)') {
            if (-not $seen['devname']) { $seen['devname'] = $true; $findings.Add((New-Finding 'medium' 'obfuscation' 'Reserved Windows device name used as a file/class name' $name $where)) }
        }
        if ($name -match '[\u200B-\u200F\u2060\uFEFF]') {
            if (-not $seen['zw']) { $seen['zw'] = $true; $findings.Add((New-Finding 'medium' 'obfuscation' 'Zero-width characters in a file/class name' (Limit-Text $name 80) $where)) }
        } elseif ($isClass -and $name -match '[\u0370-\u03FF\u0400-\u04FF]') {
            if (-not $seen['homoglyph']) { $seen['homoglyph'] = $true; $findings.Add((New-Finding 'medium' 'obfuscation' 'Cyrillic/Greek look-alike letters in a class name' (Limit-Text $name 80) $where)) }
        } elseif ($isClass -and $name -match '[\u3040-\u30FF\u4E00-\u9FFF]') {
            if (-not $seen['cjk']) { $seen['cjk'] = $true; $findings.Add((New-Finding 'medium' 'obfuscation' 'Japanese/CJK characters in class names (common obfuscation)' (Limit-Text $name 80) $where)) }
        } elseif ($name -match '[^\u0000-\u007F]') {
            if ($isClass -and -not $seen['nonascii']) { $seen['nonascii'] = $true; $findings.Add((New-Finding 'medium' 'obfuscation' 'Non-ASCII class name' (Limit-Text $name 80) $where)) }
            elseif (-not $isClass -and -not $seen['nonasciires']) { $seen['nonasciires'] = $true; $findings.Add((New-Finding 'low' 'obfuscation' 'Non-ASCII resource name' (Limit-Text $name 80) $where)) }
        }

        if ($ext -eq '.jar') {
            if ($Depth -ge 3) { $findings.Add((New-Finding 'medium' 'bypass' 'Nested archive too deep to scan (jar inside jar inside jar inside jar)' $name $where)); continue }
            $isNestDir = ($name -like 'META-INF/jars/*') -or ($name -like 'META-INF/jarjar/*')
            $nb = Read-EntryBytes $e 40MB
            if (-not $nb -and $e.Length -gt 40MB) { $findings.Add((New-Finding 'medium' 'bypass' 'Nested jar larger than 40 MB was not scanned' ("{0} MB" -f [math]::Round($e.Length / 1MB)) $where)) }
            if ($nb) {
                try {
                    $nz = New-Object IO.Compression.ZipArchive((New-Object IO.MemoryStream(, $nb)), 'Read')
                    $sub = Scan-Archive $nz $where ($Depth + 1) $State
                    foreach ($f in $sub.Findings) { $findings.Add($f) }
                    if ($pb -and $sub.Prof -and $sub.ClassCount -le 80) { $pb.Merge($sub.Prof) }
                    $nestedMeta = Get-ModMeta $nz
                    [void]$State.Nested.Add([pscustomobject]@{ File = (Limit-Text $name 100); Classes = [int]$sub.ClassCount; Id = $(if ($nestedMeta) { $nestedMeta.Id } else { $null }) })
                    $State.NestedJars++
                    if ($isNestDir) {
                        if (-not $declared.ContainsKey($name.ToLower())) { $findings.Add((New-Finding 'medium' 'bypass' 'Nested jar not declared in fabric.mod.json / jarjar metadata' $name $where)) }
                    } else {
                        $findings.Add((New-Finding 'medium' 'bypass' 'Jar hidden outside META-INF/jars' "Nested jar at '$name'" $where))
                    }
                    $nz.Dispose()
                } catch { $findings.Add((New-Finding 'low' 'bypass' 'Unreadable nested jar' (Limit-Text $_.Exception.Message 80) $where)) }
            }
            continue
        }

        if ($ext -in '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.msi', '.hta', '.com', '.lnk') {
            $findings.Add((New-Finding 'high' 'bypass' 'Executable/script payload inside jar' $name $where)); continue
        }
        if ($ext -eq '.dll') {
            $db = Read-EntryBytes $e 16MB
            if ($db) { Test-DllBytes $db $where $findings }
            continue
        }
        if ($ext -in '.so', '.dylib') { continue }

        $isText = ($ext -in '.json', '.mf', '.toml', '.txt', '.properties', '.cfg', '.xml', '.yml', '.yaml', '.info', '.conf', '.ini') -or ($name -like 'META-INF/*')
        if (-not $isClass -and -not $isText) {

            if ($magicBudget -gt 0 -and $e.Length -ge 64 -and $e.Length -le 16MB) {
                $magicBudget--
                try {
                    $st = $e.Open(); $head = New-Object byte[] 4
                    $got = $st.Read($head, 0, 4); $st.Dispose()
                    if ($got -eq 4) {
                        if ($head[0] -eq 0x4D -and $head[1] -eq 0x5A) { $findings.Add((New-Finding 'high' 'bypass' 'Windows executable disguised as a resource' $name $where)) }
                        elseif ($head[0] -eq 0xCA -and $head[1] -eq 0xFE -and $head[2] -eq 0xBA -and $head[3] -eq 0xBE -and $name -notmatch '(?i)(^|/)DebugProbesKt\.bin$') { $findings.Add((New-Finding 'high' 'bypass' 'Java class disguised as a resource' $name $where)); $dcb = Read-EntryBytes $e 4MB; if ($dcb -and $pb) { [void]$pb.AddClass($dcb, $name) } }
                        elseif ($head[0] -eq 0x50 -and $head[1] -eq 0x4B -and $head[2] -eq 0x03 -and $head[3] -eq 0x04 -and $ext -in '.png', '.jpg', '.jpeg', '.gif', '.ogg', '.wav', '.mp3', '.txt', '.lang', '.dat', '.bin', '.ico', '.bmp') {
                            $findings.Add((New-Finding 'high' 'bypass' 'Archive/jar disguised as a resource' $name $where))
                            Scan-HiddenArchive $e $where $Depth $State $findings
                        }
                    }
                } catch {}
            }

            if ($script:Native -and $e.Length -ge 8192 -and $e.Length -le 8MB -and ($ext -in '', '.dat', '.bin', '.enc', '.data', '.res', '.lib', '.tmp', '.bak', '.ser', '.cache', '.pak') -and $name -notlike 'assets/*' -and $name -notlike 'data/*') {
                $eb = Read-EntryBytes $e 8MB
                if ($eb -and [CactusHacksDetector.Util]::Entropy($eb) -ge 7.6 -and -not $seen['entropy']) {
                    $seen['entropy'] = $true
                    $findings.Add((New-Finding 'medium' 'bypass' 'High-entropy (encrypted/packed) data file' $name $where))
                }
            }
            continue
        }

        $bytes = Read-EntryBytes $e
        if (-not $bytes) {
            if ($isClass -and $e.Length -gt 12MB -and -not $seen['bigclass']) { $seen['bigclass'] = $true; $findings.Add((New-Finding 'medium' 'bypass' 'Oversized class file skipped by the scanner (padding to avoid analysis)' ("{0} MB" -f [math]::Round($e.Length / 1MB)) $where)) }
            continue
        }
        $State.BytesScanned += $bytes.Length
        $text = $Latin1.GetString($bytes)
        if (-not $isClass -and $bytes.Length -ge 4) {
            if ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and $bytes[2] -eq 3 -and $bytes[3] -eq 4) {
                $findings.Add((New-Finding 'high' 'bypass' 'Archive/jar disguised as a text or config file' $name $where))
                Scan-HiddenArchive $e $where $Depth $State $findings
            } elseif ($bytes[0] -eq 0xCA -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0xBA -and $bytes[3] -eq 0xBE) {
                $findings.Add((New-Finding 'high' 'bypass' 'Java class disguised as a text or config file' $name $where))
                if ($pb) { [void]$pb.AddClass($bytes, $name) }
            }
        }
        if ($ext -eq '.json' -and $mixCfg.Count -lt 12 -and $bytes.Length -lt 2MB -and (($name -match '(?i)(^|/)[^/]*mixins?[^/]*\.json$' -and $name -notmatch '(?i)refmap') -or $name -notmatch '/') -and $text -match '"package"\s*:' -and $text -match '"(mixins|client|server)"\s*:\s*\[') {
            try {
                $mj = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json -ErrorAction Stop
                if ($mj -and $mj.package) {
                    $mxPk = ([string]$mj.package).Replace('.', '/')
                    $mxDecl = New-Object System.Collections.Generic.List[string]
                    foreach ($mxGrp in 'mixins', 'client', 'server') { foreach ($mxn in @($mj.$mxGrp)) { if ($mxn) { $mxDecl.Add(($mxPk + '/' + ([string]$mxn).Replace('.', '/'))) } } }
                    [void]$mixCfg.Add([pscustomobject]@{ File = $name; Names = @($mxDecl); Plugin = [string]$mj.plugin })
                }
            } catch {}
        }
        if ($pb -and $Depth -eq 0 -and $langDone -lt 2 -and $ext -eq '.json' -and $name -match '(?i)^assets/[^/]+/lang/[a-z_]+\.json$') { $langDone++; $pb.AddLang([Text.Encoding]::UTF8.GetString($bytes)) }

        foreach ($mr in $MalwareRx) {
            $key = "mw|$($mr.Rule)"
            if ($seen[$key]) { continue }
            $m = $mr.Rx.Match($text)
            if ($m.Success) {
                $seen[$key] = $true
                $snippet = ($m.Value -replace '[^\x20-\x7E]', '.'); if ($snippet.Length -gt 80) { $snippet = $snippet.Substring(0, 80) }
                $findings.Add((New-Finding $mr.Sev 'malware' $mr.Rule "match '$snippet'" $where))
            }
        }
        foreach ($k in 'Clients', 'Modules', 'Bypass') {
            $m = $Rx[$k].Match($text)
            if ($m.Success -and -not $seen["s$k|$($m.Value.ToLower())"]) {
                $seen["s$k|$($m.Value.ToLower())"] = $true
                $sev = 'high'; if ($k -eq 'Modules') { $sev = 'medium' }
                $findings.Add((New-Finding $sev 'cheat-string' "$k string" "'$($m.Value)' inside file" $where))
                if ($k -eq 'Modules') { Add-Hack $State $m.Value '' "string inside $name" 'string' }
                if ($k -eq 'Clients') { Add-Hack $State $m.Value 'client' "client name inside $name" 'client' }
            }
        }
        $mk = $Rx.Markers.Match($text)
        if ($mk.Success -and -not $seen["sMarkers|$($mk.Value.ToLower())"]) {
            $seen["sMarkers|$($mk.Value.ToLower())"] = $true
            $findings.Add((New-Finding 'high' 'cheat-string' 'Hack-client marker string' "'$($mk.Value)' inside file" $where))
        }
        foreach ($lm in $Rx.Labels.Matches($text)) { $labelHits[$lm.Value.ToLower()] = $true }
        foreach ($lw in $Rx.LabelsWeak.Matches($text)) { $labelWeak[$lw.Value.ToLower()] = $true }
        $ob = $Rx.Obfuscators.Match($text)
        if ($ob.Success -and -not $seen['obf']) { $seen['obf'] = $true; $findings.Add((New-Finding 'medium' 'obfuscation' 'Obfuscator fingerprint' "'$($ob.Value)' inside file" $where)) }
        $fw = $FullwidthRx.Match($text)
        if ($fw.Success -and -not $seen['fullwidth'] -and ((Decode-Fullwidth $fw.Value) -cmatch '[A-Za-z].*[A-Za-z].*[A-Za-z]')) {
            $seen['fullwidth'] = $true
            $decoded = Decode-Fullwidth $fw.Value
            $findings.Add((New-Finding 'high' 'cheat-string' 'Fullwidth Unicode label (hides module names)' "decodes to '$decoded'" $where))
            Add-Hack $State $decoded 'hidden label' "fullwidth label in $name" 'string'
        }

        if ($isClass -and $State.ClassesParsed -ge 20000 -and -not $seen['clslimit']) { $seen['clslimit'] = $true; $findings.Add((New-Finding 'low' 'bypass' 'Class analysis limit reached, remaining classes were not analysed (possible padding)' '20000+ classes' $Label)) }
        if ($isClass -and $pb -and $profCount -lt 20000) { $profCount++; [void]$pb.AddClass($bytes, $name) }

        if ($isClass -and $script:Native -and $State.ClassesParsed -lt 20000) {
            $State.ClassesParsed++
            $ci = [CactusHacksDetector.ClassAnalyzer]::Analyze($bytes)
            if ($ci.Ok) {
                if ($name -notlike 'META-INF/versions/*') { $majors[[int]$ci.Major] = 1 + [int]$majors[[int]$ci.Major] }
                $caps = @{}; foreach ($c in $ci.Caps) { $caps[$c] = $true }
                if ($caps['listen'] -and $caps['exec'] -and -not $seen['c-shell']) { $seen['c-shell'] = $true; $findings.Add((New-Finding 'high' 'malware' 'Remote shell: listens on a socket and runs programs' $ci.ThisClass $where)) }
                elseif ($caps['exec'] -and $caps['net'] -and -not $seen['c-execnet']) { $seen['c-execnet'] = $true; $findings.Add((New-Finding 'medium' 'behavior' 'Runs programs and uses the network in the same class' $ci.ThisClass $where)) }
                elseif ($caps['exec'] -and -not $seen['c-exec']) { $seen['c-exec'] = $true; $findings.Add((New-Finding 'low' 'behavior' 'Starts external programs (Runtime.exec / ProcessBuilder)' $ci.ThisClass $where)) }
                if ($caps['classdef'] -and ($caps['b64'] -or $caps['cipher'] -or $caps['inflate']) -and -not $seen['c-loader']) { $seen['c-loader'] = $true; $findings.Add((New-Finding 'medium' 'bypass' 'Decodes data and defines classes at runtime (packed loader)' $ci.ThisClass $where)) }
                if ($caps['robot-mouse'] -and -not $seen['c-rm']) { $seen['c-rm'] = $true; $findings.Add((New-Finding 'medium' 'cheat-behavior' 'Simulates mouse clicks (java.awt.Robot) - autoclicker behaviour' $ci.ThisClass $where)) }
                if ($caps['robot-key'] -and -not $seen['c-rk']) { $seen['c-rk'] = $true; $findings.Add((New-Finding 'medium' 'cheat-behavior' 'Simulates key presses (java.awt.Robot)' $ci.ThisClass $where)) }
                if ($caps['robot-screen'] -and -not $seen['c-rs']) { $seen['c-rs'] = $true; $findings.Add((New-Finding 'medium' 'cheat-behavior' 'Takes screenshots via java.awt.Robot' $ci.ThisClass $where)) }
                if ($caps['jnativehook'] -and -not $seen['c-nh']) { $seen['c-nh'] = $true; $findings.Add((New-Finding 'medium' 'library' 'Global keyboard/mouse hook library (jnativehook)' $ci.ThisClass $where)) }
                if ($caps['glfw-callback'] -and -not $seen['c-glfw']) { $seen['c-glfw'] = $true; $findings.Add((New-Finding 'low' 'behavior' 'Installs raw GLFW input callbacks' $ci.ThisClass $where)) }
                if ($ci.StrTotal -ge 3 -and $ci.EncStr -ge 3 -and ($ci.EncStr * 2) -ge $ci.StrTotal) {
                    $encTotal++
                    $encSample = ''
                    if ($ci.EncSamples.Count -gt 0) { $encSample = $ci.EncSamples[0] }
                    if ($encClasses.Count -lt 200) { $encClasses.Add(("{0} ({1}/{2} strings, e.g. '{3}')" -f $ci.ThisClass, $ci.EncStr, $ci.StrTotal, $encSample)) }
                    if ($ci.DecryptRefs -ge 1) { $encDec++ }
                }
                $ldr = ($ci.SuperClass -eq 'java/lang/ClassLoader' -or $ci.SuperClass -eq 'java/net/URLClassLoader' -or $ci.SuperClass -eq 'java/security/SecureClassLoader')
                if ($ldr -or $caps['classdef'] -or $caps['attach'] -or $caps['instrument'] -or $caps['mixin-dyn']) {
                    if ($ci.ThisClass -notmatch $libRx) {
                        $capList = (@($ci.Caps) | Sort-Object) -join ','
                        if ($ldr -and -not $seen['c-ldr']) {
                            $seen['c-ldr'] = $true
                            $lsev = 'low'
                            if ($caps['resource-read'] -or $caps['b64'] -or $caps['cipher'] -or $caps['inflate'] -or $caps['net']) { $lsev = 'medium' }
                            $findings.Add((New-Finding $lsev 'bypass' 'Custom ClassLoader subclass (can load code that is not visible in the jar)' ("{0} extends {1} [{2}]" -f $ci.ThisClass, $ci.SuperClass, $capList) $where))
                        }
                        if ($caps['classdef'] -and $caps['resource-read'] -and -not $seen['c-resdef']) {
                            $seen['c-resdef'] = $true
                            $findings.Add((New-Finding 'medium' 'bypass' 'Reads a packed resource and defines classes from it (hidden payload loader)' ("{0} [{1}]" -f $ci.ThisClass, $capList) $where))
                        }
                        if ($caps['classdef'] -and $caps['net'] -and -not $seen['c-netdef']) {
                            $seen['c-netdef'] = $true
                            $findings.Add((New-Finding 'medium' 'bypass' 'Loads classes dynamically and uses URLs or sockets in the same class (possible remote code loader)' ("{0} [{1}]" -f $ci.ThisClass, $capList) $where))
                        }
                        if (($caps['attach'] -or $caps['instrument']) -and -not $seen['c-agent']) {
                            $seen['c-agent'] = $true
                            $findings.Add((New-Finding 'medium' 'bypass' 'Attaches a Java agent or instruments classes at runtime' ("{0} [{1}]" -f $ci.ThisClass, $capList) $where))
                        }
                        if ($caps['mixin-dyn']) { $mixDyn = $true }
                    }
                }
                foreach ($kp in $ci.Keys) {
                    [void]$State.Keys.Add([pscustomobject]@{ Name = $kp.Name; Key = $kp.Key; Owner = $kp.Owner; Major = $ci.Major; Caps = @($ci.Caps); Class = $ci.ThisClass })
                }
            }
        }
    }

    if ($encTotal -ge 3) {
        $esev = 'low'
        if ($encTotal -ge 6 -and $encDec -ge 3) { $esev = 'medium' }
        $findings.Add((New-Finding $esev 'obfuscation' 'String encryption: constants are stored as unreadable text' ("{0} classes ({1} with a string decryptor method), e.g. {2}" -f $encTotal, $encDec, ((@($encClasses) | Select-Object -First 3) -join '; ')) $Label))
    }

    if ($pb) {
        $mxNames = @($pb.MixinNames())
        if ($mixCfg.Count -gt 0 -or $mxNames.Count -gt 0) {
            $classSet = @{}
            foreach ($cn in $classNames) { $classSet[$cn] = $true }
            $declAll = @{}
            $missingMx = New-Object System.Collections.Generic.List[string]
            $plugins = New-Object System.Collections.Generic.List[string]
            foreach ($mcfg in $mixCfg) {
                foreach ($dn in $mcfg.Names) { $declAll[$dn] = $true; if (-not $classSet.ContainsKey($dn)) { $missingMx.Add($dn) } }
                if ($mcfg.Plugin) { $plugins.Add($mcfg.Plugin) }
            }
            $undecl = @($mxNames | Where-Object { -not $declAll.ContainsKey($_) })
            if ($missingMx.Count -ge 1) {
                $msev = 'low'
                if ($missingMx.Count -ge 3) { $msev = 'medium' }
                $findings.Add((New-Finding $msev 'bypass' 'Mixin config lists classes that are not in the jar (code may be loaded from elsewhere)' ("{0} missing, e.g. {1}" -f $missingMx.Count, ((@($missingMx) | Select-Object -First 3) -join ', ')) $Label))
            }
            if ($undecl.Count -ge 1) {
                $usev = 'low'
                $plugTxt = ''
                if ($plugins.Count -gt 0) { $plugTxt = '; mixin plugin ' + $plugins[0] }
                if ($plugins.Count -gt 0 -or $mixDyn) { $usev = 'medium' }
                $findings.Add((New-Finding $usev 'bypass' 'Mixin classes that no mixin config declares (hidden or dynamically registered mixins)' ("{0} undeclared, e.g. {1}{2}" -f $undecl.Count, ((@($undecl) | Select-Object -First 3) -join ', '), $plugTxt) $Label))
            }
        }
    }

    if ($labelHits.Count -ge 4) {
        $findings.Add((New-Finding 'high' 'cheat-string' 'Cheat module setting labels' ((@($labelHits.Keys) | Select-Object -First 6) -join ', ') $Label))
    } elseif (($labelHits.Count + $labelWeak.Count) -ge 5) {
        $findings.Add((New-Finding 'medium' 'cheat-string' 'Setting labels typical of combat/utility cheat modules' ((@($labelHits.Keys) + @($labelWeak.Keys) | Select-Object -First 6) -join ', ') $Label))
    }

    if ($moduleCount -ge 12 -and $moduleDirs.Count -ge 2) {
        $findings.Add((New-Finding 'medium' 'cheat-name' 'Hack-client style module tree (modules/<category>/<Module>)' ("{0} classes in {1} module folders: {2}" -f $moduleCount, $moduleDirs.Count, ((@($moduleDirs.Keys) | Select-Object -First 6) -join ', ')) $Label))
    }

    if ($pb) {
        $behN = 0; $behCombat = 0
        foreach ($bh in $pb.Behaviors()) {
            $behN++
            if ([string]$bh[0] -match '(?i)aura|triggerbot|reach|aim|velocity|knockback|criticals|swap|crystal|anchor|hitbox') { $behCombat++ }
            $findings.Add((New-Finding 'medium' 'cheat-behavior' $bh[0] (Limit-Text $bh[1] 160) $Label))
            $bn = [regex]::Match([string]$bh[0], '\(([^()]+?) behaviour\)\s*$')
            if ($bn.Success) { Add-Hack $State (($bn.Groups[1].Value -replace '\s*/\s*', '/') + ' (behaviour)') '' ([string]$bh[0]) 'behavior' }
        }
        if ($encTotal -ge 3 -and $behN -ge 1 -and $behCombat -ge 1) {
            $findings.Add((New-Finding 'high' 'cheat-behavior' 'Cheat behaviour in code whose strings are encrypted (module names are hidden)' ("{0} classes with encrypted strings and {1} cheat behaviour(s)" -f $encTotal, $behN) $Label))
        }
        foreach ($hh in $pb.Hierarchy()) {
            $findings.Add((New-Finding 'medium' 'cheat-behavior' 'Module-style class hierarchy using attack, rotation, packet or inventory APIs (works with renamed classes)' ("{0} classes extend {1}, {2} of them use such APIs: {3}" -f $hh[1], $hh[0], $hh[2], $hh[3]) $Label))
        }
        $vt = @($pb.VocabTerms())
        if ($vt.Count -ge 3) {
            $findings.Add((New-Finding 'medium' 'cheat-name' 'Cheat-module vocabulary in class, method and string names' ("{0} terms: {1}" -f $vt.Count, (($vt | Select-Object -First 10) -join ', ')) $Label))
        }
        if ($vt.Count -ge 4 -and $Depth -eq 0) {
            foreach ($vh in ($vt | Select-Object -First 12)) { Add-Hack $State $vh '' 'name found in class, method or string names' 'string' }
        }
    }

    if ($weak.Count -ge 3) {
        $findings.Add((New-Finding 'medium' 'cheat-name' 'Several generic module-style class names (esp/fly/velocity/...)' ("{0}: {1}" -f $weak.Count, ((@($weak.Keys) | Select-Object -First 8) -join ', ')) $Label))
        foreach ($wk in $weak.Keys) { Add-Hack $State $wk '' "class named $wk" 'weak' }
    }

    if ($classNames.Count -ge 20) {
        $short = 0; $junk = 0; $digits = 0
        foreach ($cn in $classNames) {
            $leaf = $cn.Substring($cn.LastIndexOf('/') + 1)
            if ($leaf.Length -le 2) { $short++ }
            if ($leaf -match '^[Il1O0_]{3,}$') { $junk++ }
            if ($leaf -match '^\d+$') { $digits++ }
        }
        $total = $classNames.Count
        $pShort = [math]::Round(100 * $short / $total); $pJunk = [math]::Round(100 * $junk / $total)
        if ($pJunk -ge 20) { $findings.Add((New-Finding 'medium' 'obfuscation' 'Look-alike class names (I/l/1/O/0)' "$pJunk% of $total classes" $Label)) }
        elseif ($pShort -ge 60) { $findings.Add((New-Finding 'low' 'obfuscation' 'Mostly 1-2 letter class names' "$pShort% of $total classes" $Label)) }
        if ($digits -ge 10) { $findings.Add((New-Finding 'medium' 'obfuscation' 'Numeric class names' "$digits classes" $Label)) }
        $deep = 0; foreach ($cn in $classNames) { if ($cn -match '^([a-z]/){4,}') { $deep++ } }
        if ($deep -ge 10) { $findings.Add((New-Finding 'medium' 'obfuscation' 'Deep single-letter package paths (a/b/c/d/...)' "$deep classes" $Label)) }
    }

    if ($majors.Count -ge 2) {
        $tot = 0; foreach ($v in $majors.Values) { $tot += $v }
        foreach ($mj in $majors.Keys) {
            if ($majors[$mj] -le 3 -and $tot -ge 25) {
                $findings.Add((New-Finding 'low' 'bypass' 'A few classes use a different Java version than the rest' ("{0} class(es) with class-file version {1}" -f $majors[$mj], $mj) $Label))
            }
        }
    }

    if ($platform) {
        for ($fi = $findings.Count - 1; $fi -ge 0; $fi--) {
            if ($findings[$fi].Category -in 'cheat-name', 'cheat-string', 'cheat-behavior', 'obfuscation', 'library') { $findings.RemoveAt($fi) }
        }
        foreach ($hk in @($State.Hacks.Keys)) { if ($hackKeysBefore -notcontains $hk) { $State.Hacks.Remove($hk) } }
    }

    [pscustomobject]@{ Findings = $findings; ClassCount = $classNames.Count; Prof = $pb; Res = $resNames }
}

function Get-ModrinthMatches([hashtable]$Sha1ToPath) {
    $result = @{}
    if ($NoOnline -or $Sha1ToPath.Count -eq 0) { return $result }
    $headers = @{ 'User-Agent' = "CactusHacksDetector/$ScriptVersion (read-only mod scanner)" }
    try {
        $body = @{ hashes = @($Sha1ToPath.Keys); algorithm = 'sha1' } | ConvertTo-Json -Compress
        $versions = Invoke-RestMethod -Method Post -Uri 'https://api.modrinth.com/v2/version_files' -Headers $headers `
            -ContentType 'application/json' -Body $body -TimeoutSec 30
        $projIds = @()
        foreach ($h in $versions.PSObject.Properties.Name) { $projIds += $versions.$h.project_id }
        $titles = @{}
        $projIds = @($projIds | Select-Object -Unique)
        for ($i = 0; $i -lt $projIds.Count; $i += 100) {
            $chunk = $projIds[$i..([math]::Min($i + 99, $projIds.Count - 1))]
            $ids = '["' + ($chunk -join '","') + '"]'
            $projs = Invoke-RestMethod -Uri ('https://api.modrinth.com/v2/projects?ids=' + [uri]::EscapeDataString($ids)) -Headers $headers -TimeoutSec 30
            foreach ($p in $projs) { $titles[$p.id] = $p.title }
        }
        foreach ($h in $versions.PSObject.Properties.Name) {
            $v = $versions.$h
            $result[$h] = [pscustomobject]@{ Project = $titles[$v.project_id]; Version = $v.version_number; Slug = $v.project_id }
        }
    } catch {
        Write-Line "  (Modrinth lookup unavailable: $($_.Exception.Message))" DarkYellow
    }
    return $result
}

function Get-DownloadSource([string]$Path) {
    try {
        $z = Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop
        $host_ = ($z | Where-Object { $_ -like 'HostUrl=*' } | Select-Object -First 1) -replace '^HostUrl=', ''
        $ref   = ($z | Where-Object { $_ -like 'ReferrerUrl=*' } | Select-Object -First 1) -replace '^ReferrerUrl=', ''
        $u = if ($host_ -and $host_ -ne 'about:internet') { $host_ } else { $ref }
        if (-not $u) { return [pscustomobject]@{ Url = $null; Trust = 'unknown' } }
        $trust = 'verify'
        if ($u -match '(?i)modrinth\.com|cdn\.modrinth|curseforge\.com|forgecdn\.net|papermc\.io|fabricmc\.net|minecraftforge\.net') { $trust = 'safe' }
        elseif ($u -match '(?i)github\.com|githubusercontent\.com') { $trust = 'verify' }
        elseif ($u -match '(?i)discord(app)?\.com|cdn\.discordapp|mediafire|mega\.nz|dropbox|drive\.google|anydesk|doomsday|prestige|198macros|dqrkis|telegram|t\.me|temp\.sh|file\.io|anonfiles|catbox') { $trust = 'risky' }
        $short = $u; if ($short.Length -gt 90) { $short = $short.Substring(0, 90) + '...' }
        return [pscustomobject]@{ Url = $short; Trust = $trust }
    } catch { return [pscustomobject]@{ Url = $null; Trust = 'unknown' } }
}

function Get-ModMeta($Zip) {
    $meta = [ordered]@{ Id = $null; Name = $null; Version = $null; Loader = $null; Authors = @(); Description = $null; Homepage = $null; Entrypoints = @(); MixinConfigs = @(); Depends = @() }
    $fab = $Zip.GetEntry('fabric.mod.json'); $qlt = $Zip.GetEntry('quilt.mod.json')
    $toml = $Zip.GetEntry('META-INF/mods.toml'); if (-not $toml) { $toml = $Zip.GetEntry('META-INF/neoforge.mods.toml') }
    $old = $Zip.GetEntry('mcmod.info')
    $read = { param($en) $b = Read-EntryBytes $en 2MB; if ($b) { [Text.Encoding]::UTF8.GetString($b) } }
    $nameOf = { param($v) if ($v -is [string]) { $v } elseif ($v -and $v.name) { [string]$v.name } else { $null } }
    if ($fab) {
        $t = & $read $fab; $meta.Loader = 'fabric'
        if ($t -match '"id"\s*:\s*"([^"]+)"') { $meta.Id = $Matches[1] }
        if ($t -match '"name"\s*:\s*"([^"]+)"') { $meta.Name = $Matches[1] }
        if ($t -match '"version"\s*:\s*"([^"]+)"') { $meta.Version = $Matches[1] }
        $j = $null
        try { $j = $t | ConvertFrom-Json -ErrorAction Stop } catch {}
        if ($j) {
            $meta.Authors = @(@($j.authors) | ForEach-Object { & $nameOf $_ } | Where-Object { $_ } | Select-Object -First 6)
            if ($j.description) { $meta.Description = Limit-Text ([string]$j.description) 240 }
            if ($j.contact -and $j.contact.homepage) { $meta.Homepage = Limit-Text ([string]$j.contact.homepage) 120 }
            elseif ($j.contact -and $j.contact.sources) { $meta.Homepage = Limit-Text ([string]$j.contact.sources) 120 }
            $eps = New-Object System.Collections.Generic.List[string]
            if ($j.entrypoints) {
                foreach ($pr in $j.entrypoints.PSObject.Properties) {
                    foreach ($v in @($pr.Value)) {
                        $sv = $null
                        if ($v -is [string]) { $sv = $v } elseif ($v -and $v.value) { $sv = [string]$v.value }
                        if ($sv) { $eps.Add(('{0}:{1}' -f $pr.Name, $sv)) }
                    }
                }
            }
            $meta.Entrypoints = @($eps | Select-Object -First 10)
            $meta.MixinConfigs = @(@($j.mixins) | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_ -and $_.config) { [string]$_.config } } | Where-Object { $_ } | Select-Object -First 8)
            if ($j.depends) { $meta.Depends = @($j.depends.PSObject.Properties.Name | Select-Object -First 15) }
        }
    } elseif ($qlt) {
        $t = & $read $qlt; $meta.Loader = 'quilt'
        if ($t -match '"id"\s*:\s*"([^"]+)"') { $meta.Id = $Matches[1] }
        if ($t -match '"version"\s*:\s*"([^"]+)"') { $meta.Version = $Matches[1] }
        if ($t -match '"name"\s*:\s*"([^"]+)"') { $meta.Name = $Matches[1] }
        if ($t -match '"description"\s*:\s*"([^"]+)"') { $meta.Description = Limit-Text $Matches[1] 240 }
        try {
            $qj = $t | ConvertFrom-Json -ErrorAction Stop
            $ql = $qj.quilt_loader
            if ($ql -and $ql.metadata) {
                if ($ql.metadata.contributors) { $meta.Authors = @($ql.metadata.contributors.PSObject.Properties.Name | Select-Object -First 6) }
                if ($ql.metadata.contact -and $ql.metadata.contact.homepage) { $meta.Homepage = Limit-Text ([string]$ql.metadata.contact.homepage) 120 }
            }
            if ($ql -and $ql.entrypoints) {
                $qe = New-Object System.Collections.Generic.List[string]
                foreach ($pr in $ql.entrypoints.PSObject.Properties) {
                    foreach ($v in @($pr.Value)) {
                        $sv = $null
                        if ($v -is [string]) { $sv = $v } elseif ($v -and $v.value) { $sv = [string]$v.value }
                        if ($sv) { $qe.Add(('{0}:{1}' -f $pr.Name, $sv)) }
                    }
                }
                $meta.Entrypoints = @($qe | Select-Object -First 10)
            }
            if ($qj.mixin) { $meta.MixinConfigs = @(@($qj.mixin) | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_ -and $_.config) { [string]$_.config } } | Where-Object { $_ } | Select-Object -First 8) }
            if ($ql -and $ql.depends) { $meta.Depends = @(@($ql.depends) | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_ -and $_.id) { [string]$_.id } } | Where-Object { $_ } | Select-Object -First 15) }
        } catch {}
    } elseif ($toml) {
        $t = & $read $toml; $meta.Loader = 'forge/neoforge'; if ($Zip.GetEntry('META-INF/neoforge.mods.toml') -and -not $Zip.GetEntry('META-INF/mods.toml')) { $meta.Loader = 'neoforge' }
        if ($t -match 'modId\s*=\s*"([^"]+)"') { $meta.Id = $Matches[1] }
        if ($t -match 'displayName\s*=\s*"([^"]+)"') { $meta.Name = $Matches[1] }
        if ($t -match '(?m)^\s*version\s*=\s*"([^"]+)"') { $meta.Version = $Matches[1] }
        if ($t -match '(?m)^\s*authors\s*=\s*"([^"]+)"') { $meta.Authors = @($Matches[1]) }
        if ($t -match "(?s)description\s*=\s*'''(.*?)'''") { $meta.Description = Limit-Text $Matches[1] 240 }
        elseif ($t -match '(?m)^\s*description\s*=\s*"([^"]*)"') { $meta.Description = Limit-Text $Matches[1] 240 }
        if ($t -match '(?m)^\s*displayURL\s*=\s*"([^"]+)"') { $meta.Homepage = Limit-Text $Matches[1] 120 }
        $ids = @([regex]::Matches($t, '(?m)modId\s*=\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        if ($ids.Count -gt 1) { $meta.Depends = @($ids | Select-Object -Skip 1 -First 15) }
        $meta.MixinConfigs = @([regex]::Matches($t, 'config\s*=\s*"([^"]+\.json)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -First 8)
    } elseif ($old) {
        $t = & $read $old; $meta.Loader = 'legacy forge'
        if ($t -match '"modid"\s*:\s*"([^"]+)"') { $meta.Id = $Matches[1] }
        if ($t -match '"name"\s*:\s*"([^"]+)"') { $meta.Name = $Matches[1] }
        if ($t -match '"description"\s*:\s*"([^"]+)"') { $meta.Description = Limit-Text $Matches[1] 240 }
        if ($t -match '"url"\s*:\s*"([^"]+)"') { $meta.Homepage = Limit-Text $Matches[1] 120 }
        if ($t -match '"authorList"\s*:\s*\[([^\]]*)\]') { $meta.Authors = @([regex]::Matches($Matches[1], '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -First 6) }
    }
    [pscustomobject]$meta
}

function New-ModProfile($Prof, $Meta, $ResNames, $State) {
    try {
        $p = ConvertFrom-Json (Hide-User ($Prof.Build(8200)))
        $m = [ordered]@{ id = $null; name = $null; version = $null; loader = $null; authors = @(); description = $null; homepage = $null; entrypoints = @(); mixinConfigs = @(); depends = @() }
        if ($Meta) {
            $m.id = $Meta.Id; $m.name = $Meta.Name; $m.version = $Meta.Version; $m.loader = $Meta.Loader
            $m.authors = @($Meta.Authors); $m.description = $Meta.Description; $m.homepage = $Meta.Homepage
            $m.entrypoints = @($Meta.Entrypoints); $m.mixinConfigs = @($Meta.MixinConfigs); $m.depends = @($Meta.Depends)
        }
        $p | Add-Member -NotePropertyName meta -NotePropertyValue $m -Force
        $first = New-Object System.Collections.Generic.List[string]
        $rest = New-Object System.Collections.Generic.List[string]
        foreach ($rn in @($ResNames)) {
            if (-not $rn) { continue }
            if ($rn -match '(?i)\.mixins?\.json$|\.accesswidener$|accesstransformer\.cfg$') { $first.Add($rn) }
            elseif ($rn -notmatch '(?i)^(assets/|META-INF/(MANIFEST|services/|maven/|versions/)|.*\.(SF|RSA|DSA|kotlin_module|kotlin_builtins)$)') { $rest.Add($rn) }
        }
        $resOut = @((@($first) + @($rest)) | Select-Object -Unique | Select-Object -First 30 | ForEach-Object { Limit-Text $_ 90 })
        $p | Add-Member -NotePropertyName resources -NotePropertyValue $resOut -Force
        $nestedOut = @(@($State.Nested) | Select-Object -First 8 | ForEach-Object { [ordered]@{ file = $_.File; classes = [int]$_.Classes; id = $_.Id } })
        $p | Add-Member -NotePropertyName nested -NotePropertyValue $nestedOut -Force
        return $p
    } catch { return $null }
}

$script:CacheFile = $null
if ($env:LOCALAPPDATA) { $script:CacheFile = Join-Path (Join-Path $env:LOCALAPPDATA 'CactusScan') 'verified-cache.json' }
$script:VerifiedCache = @{}
$script:VerifiedOver = $false
$script:VerifiedSpent = 0.0
$script:LastSkipWhy = ''
$script:CacheVer = ''

function Get-CacheVersion {
    try {
        $src = [string]$script:ProfilerSource + [string]$Rx.Clients + [string]$Rx.Modules + 'cache-v1'
        $sha = [Security.Cryptography.SHA1]::Create()
        $hb = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($src))
        return ([BitConverter]::ToString($hb) -replace '-', '').ToLower()
    } catch { return 'none' }
}

function Read-VerifiedCache {
    $script:VerifiedCache = @{}
    $script:CacheVer = Get-CacheVersion
    try {
        if ($script:CacheFile -and (Test-Path -LiteralPath $script:CacheFile)) {
            $o = Get-Content -LiteralPath $script:CacheFile -Raw | ConvertFrom-Json
            if ($o -and [string]$o.ver -eq $script:CacheVer) { foreach ($h in @($o.sha1)) { if ($h) { $script:VerifiedCache[[string]$h] = $true } } }
        }
    } catch {}
}

function Write-VerifiedCache {
    try {
        if (-not $script:CacheFile) { return }
        $dir = Split-Path -Parent $script:CacheFile
        if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        $o = [ordered]@{ ver = $script:CacheVer; sha1 = @($script:VerifiedCache.Keys | Select-Object -First 6000) }
        ($o | ConvertTo-Json -Compress) | Set-Content -LiteralPath $script:CacheFile -Encoding ASCII
    } catch {}
}

$script:NestedIds = @{}
function ConvertTo-IdKey([string]$s) { return (([string]$s).ToLower() -replace '[^a-z0-9]', '') }
function Add-NestedIds($Zip, $Meta) {
    try {
        foreach ($e in $Zip.Entries) {
            if ($e.FullName -notmatch '(?i)^META-INF/(jars|jarjar)/.+\.jar$') { continue }
            $leaf = [IO.Path]::GetFileNameWithoutExtension($e.Name)
            $stem = $leaf -replace '(?i)[-_+]v?\d[\w.+-]*$', ''
            $k = ConvertTo-IdKey $stem
            if ($k.Length -ge 3) { $script:NestedIds[$k] = $true }
        }
        $fab = $Zip.GetEntry('fabric.mod.json')
        if ($fab) {
            $b = Read-EntryBytes $fab 2MB
            if ($b) {
                $t = [Text.Encoding]::UTF8.GetString($b)
                $pm = [regex]::Match($t, '"provides"\s*:\s*\[([^\]]*)\]')
                if ($pm.Success) { foreach ($q in [regex]::Matches($pm.Groups[1].Value, '"([^"]+)"')) { $script:NestedIds[(ConvertTo-IdKey $q.Groups[1].Value)] = $true } }
            }
        }
    } catch {}
}

function Test-KnownLoadedId([string]$Id, $KnownModIds) {
    if ($KnownModIds.ContainsKey($Id)) { return $true }
    $k = ConvertTo-IdKey $Id
    if (-not $k) { return $true }
    if ($script:NestedIds.ContainsKey($k)) { return $true }
    foreach ($n in $script:NestedIds.Keys) { if ($n.Length -ge 5 -and ($n.StartsWith($k) -or $k.StartsWith($n))) { return $true } }
    foreach ($m in $KnownModIds.Keys) { $mk = ConvertTo-IdKey $m; if ($mk.Length -ge 4 -and ($mk.StartsWith($k) -or $k.StartsWith($mk))) { return $true } }
    if ($Id -match '(?i)(^|[-_.])(api|lib|library|libs|core|common|base|config|compat|mixin|mixinextras|kotlin|scala|annotations|gson|jackson|netty|guava|placeholder)([-_.]|$)') { return $true }
    if ($Id -match '(?i)^(com|org|net|io|dev|me|de|team|maven|io_github|com_github|org_jetbrains)[-_.]') { return $true }
    if ($Id -match '(?i)^(cloth|cardinal|porting|forgeconfig|forge_config|fabric|quilt|architectury|owo|geckolib|midnightlib|yet_another_config|yacl|modmenu|java|minecraft|mixinsquared|jamlib|balm|collective|resourcefullib|playeranimator|bendylib|trinkets|accessories|sodium|iris|indium|lithium|kotlin)') { return $true }
    return $false
}

function Invoke-JarScan([IO.FileInfo]$File, $Hashes, $Modrinth) {
    $sha1 = $Hashes.Sha1
    $state = [pscustomobject]@{ NestedJars = 0; BytesScanned = 0; ClassesParsed = 0; Hacks = @{}; Keys = (New-Object System.Collections.Generic.List[object]); Nested = (New-Object System.Collections.Generic.List[object]) }
    $findings = New-Object System.Collections.Generic.List[object]
    $meta = $null; $classCount = 0; $err = $null; $skipped = $false; $prof = $null; $resNames = $null

    $verified = [bool]($Modrinth -and $sha1 -and $Modrinth.ContainsKey($sha1))
    $fs = $null; $zip = $null
    try {
        $fs = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite, Delete')
        $zip = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Read)
        $meta = Get-ModMeta $zip
        Add-NestedIds $zip $meta
        $script:LastSkipWhy = ''
        if ($verified -and $SkipVerified) { $skipped = $true; $script:LastSkipWhy = 'option' }
        elseif ($verified -and $script:VerifiedCache -and $script:VerifiedCache.ContainsKey($sha1)) { $skipped = $true; $script:LastSkipWhy = 'cache' }
        elseif ($verified -and $script:VerifiedOver) { $skipped = $true; $script:LastSkipWhy = 'budget' }
        else {
            $r = Scan-Archive $zip $File.Name 0 $state
            foreach ($f in $r.Findings) { $findings.Add($f) }
            $classCount = $r.ClassCount
            $prof = $r.Prof
            $resNames = $r.Res
        }
    } catch { $err = $_.Exception.Message }
    finally { if ($zip) { $zip.Dispose() }; if ($fs) { $fs.Dispose() } }

    $src = Get-DownloadSource $File.FullName

    $inactive = ($File.Extension -in '.disabled', '.old', '.bak', '.duplicate', '.backup', '.off', '.orig', '.prev') -or ($File.Name -match '(?i)\.jar\.[a-z0-9_-]{1,12}$')
    $modrinthTitle = $null; if ($verified) { $modrinthTitle = [string]$Modrinth[$sha1].Project }
    $policy = Get-PolicyMod $meta $File.Name $modrinthTitle
    $legit = Get-LegitMod $meta $File.Name $modrinthTitle
    if ($legit -and $policy -and $policy.Kind -eq 'suspect') { $policy = $null }
    if ($policy) {
        if ($policy.Kind -eq 'banned') { $findings.Add((New-Finding 'high' 'policy' 'Banned mod' ("'{0}' is on the banned mods list" -f $policy.Name) $File.Name)) }
        else { $findings.Add((New-Finding 'medium' 'policy' 'Suspect mod (allowed only if staff approves it)' ("'{0}' is on the suspect mods list" -f $policy.Name) $File.Name)) }
    }

    foreach ($hv in $Hashes.Sha1, $Hashes.Sha256, $Hashes.Md5) {
        if ($hv -and $script:BadHashes.ContainsKey($hv)) { $findings.Add((New-Finding 'high' 'cheat-name' 'File hash is on the known-bad list' $script:BadHashes[$hv] $File.Name)) }
    }
    if (-not $skipped -and -not $err -and -not $inactive -and $meta -and -not $meta.Id -and $classCount -gt 0) { $findings.Add((New-Finding 'low' 'metadata' 'No mod metadata (fabric.mod.json / mods.toml / mcmod.info)' $File.Name $File.Name)) }
    if ($inactive -and -not $err) { $findings.Add((New-Finding 'low' 'inactive' 'Inactive copy (the game does not load this file)' $File.Name $File.Name)) }
    elseif ($File.Extension -ne '.jar' -and -not $err -and -not $verified) { $findings.Add((New-Finding 'medium' 'bypass' 'Archive hiding under a non-.jar name in the mods folder' $File.Name $File.Name)) }
    if ($meta -and $meta.Id -and ($Sig.FakeIds -contains $meta.Id.ToLower()) -and -not $verified -and -not $NoOnline) {
        $findings.Add((New-Finding 'high' 'bypass' 'Claims to be a well-known mod but hash is not on Modrinth' "id '$($meta.Id)'" $File.Name))
    }
    if ($src.Trust -eq 'risky') { $findings.Add((New-Finding 'medium' 'source' 'Downloaded from a risky source' $src.Url $File.Name)) }
    if ($err) { $findings.Add((New-Finding 'low' 'error' 'Could not open as zip/jar (corrupt or not a jar)' (Limit-Text $err 100) $File.Name)) }
    if (($File.Attributes -band [IO.FileAttributes]::Hidden) -or ($File.Attributes -band [IO.FileAttributes]::System)) {
        $hsev = 'high'
        if ($verified) { $hsev = 'medium' }
        $findings.Add((New-Finding $hsev 'bypass' 'Mod file is hidden with the Hidden/System attribute (not visible in Explorer)' $File.Name $File.Name))
    }
    if ($File.LastWriteTimeUtc -gt $script:NowUtc.AddDays(2)) { $findings.Add((New-Finding 'medium' 'bypass' 'File timestamp is in the future (timestamps may have been altered)' ($File.LastWriteTimeUtc.ToString('o')) $File.Name)) }
    if (-not $skipped) {
        if ($classCount -le 3 -and $state.NestedJars -ge 1) { $findings.Add((New-Finding 'medium' 'bypass' 'Hollow shell: almost no classes, wraps another jar' "$classCount classes + $($state.NestedJars) nested jar(s)" $File.Name)) }
        try {
            $ads = @(Get-Item -LiteralPath $File.FullName -Stream * -ErrorAction Stop | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' })
            if ($ads.Count -gt 0) { $findings.Add((New-Finding 'medium' 'bypass' 'Hidden NTFS data stream attached to the jar' (($ads | ForEach-Object { $_.Stream }) -join ', ') $File.Name)) }
        } catch {}
        if (-not $verified) {
            if ($script:JvmStartUtc -and $File.LastWriteTimeUtc -gt $script:JvmStartUtc) {
                $findings.Add((New-Finding 'medium' 'timeline' 'File changed after the game was started (possible hot-swap)' $File.LastWriteTimeUtc.ToString('o') $File.Name))
            } elseif (Test-InWindow $File.LastWriteTimeUtc) {
                $findings.Add((New-Finding 'low' 'timeline' 'Unverified file added/changed inside the lookback window' $File.LastWriteTimeUtc.ToString('o') $File.Name))
            }
        }
    }

    foreach ($kp in $state.Keys) {
        $norm = ($kp.Name.ToLower() -replace '[^a-z0-9]', '')
        $isKeyBinding = ($kp.Owner -match '(?i)key(bind|mapping)|hotkey') -or ($kp.Name -match '^key\.')
        $kname = Format-KeyCode $kp.Key $kp.Major $kp.Caps
        if ($state.Hacks.ContainsKey($norm)) {
            $h = $state.Hacks[$norm]
            if (-not $h.Keybind) { $h.Keybind = $kname; $h.KeybindSource = "default key in code ($($kp.Class))" }
        } elseif ($Rx.Modules.IsMatch($kp.Name) -or $Rx.Clients.IsMatch($kp.Name)) {
            Add-Hack $state $kp.Name '' "module registered in $($kp.Class)" 'code'
            $h = $state.Hacks[$norm]; if ($h -and -not $h.Keybind) { $h.Keybind = $kname; $h.KeybindSource = "default key in code ($($kp.Class))" }
        }
    }
    $hasCoreEvidence = (@($findings | Where-Object { $_.Severity -in 'high', 'medium' -and $_.Category -in 'cheat-name', 'cheat-string', 'cheat-behavior', 'bypass', 'native', 'policy' }).Count -gt 0) -or ($state.Hacks.Count -gt 0)
    if ($hasCoreEvidence) {
        $extra = 0
        foreach ($kp in $state.Keys) {
            if ($extra -ge 12) { break }
            $isKeyBinding = ($kp.Owner -match '(?i)key(bind|mapping)|hotkey') -or ($kp.Name -match '^key\.')
            if ($isKeyBinding) {
                $kn = ($kp.Name.ToLower() -replace '[^a-z0-9]', '')
                if (-not $state.Hacks.ContainsKey($kn)) {
                    Add-Hack $state $kp.Name 'keybinding' "key binding registered in $($kp.Class)" 'keybinding'
                    $h = $state.Hacks[$kn]; if ($h) { $h.Kind = 'Keybind'; $h.Keybind = (Format-KeyCode $kp.Key $kp.Major $kp.Caps); $h.KeybindSource = "default key in code ($($kp.Class))" }
                    $extra++
                }
            }
        }
    }
    $strongHacks = @($state.Hacks.Values | Where-Object { $_.Strength -notin 'weak', 'keybinding', 'behavior' })
    $codeHacks = @($state.Hacks.Values | Where-Object { $_.Strength -in 'name', 'class', 'client', 'code' })
    if ($strongHacks.Count -ge 3 -or $codeHacks.Count -ge 2) {
        $findings.Add((New-Finding 'high' 'cheat-name' 'Module list consistent with a hack client' ("{0} modules: {1}" -f $strongHacks.Count, ((@($strongHacks | Select-Object -First 8 | ForEach-Object { $_.Name })) -join ', ')) $File.Name))
    }

    $behFindings = @($findings | Where-Object { $_.Category -eq 'cheat-behavior' -and $_.Severity -eq 'medium' })
    $combatBeh = @($behFindings | Where-Object { $_.Rule -match '(?i)aura|triggerbot|reach|aim|velocity|knockback|criticals|swap|crystal|anchor|hitbox' })
    if ($behFindings.Count -ge 3 -and $combatBeh.Count -ge 1 -and -not $verified) {
        $findings.Add((New-Finding 'high' 'cheat-behavior' 'Several different cheat behaviours in one mod' ((@($behFindings | Select-Object -First 4 | ForEach-Object { $_.Rule })) -join ' | ') $File.Name))
    }
    $clientStr = @($findings | Where-Object { $_.Rule -eq 'Clients string' })
    if ($clientStr.Count -eq 1 -and $codeHacks.Count -eq 0 -and @($findings | Where-Object { $_.Severity -eq 'high' -and $_.Rule -ne 'Clients string' }).Count -eq 0) {
        $clientStr[0].Severity = 'medium'
        $clientStr[0].Detail = ([string]$clientStr[0].Detail + ' (single mention, may be a compatibility check)')
    }

    if ($legit -and -not $verified -and -not $inactive -and @($findings | Where-Object { $_.Severity -eq 'high' }).Count -eq 0) {
        $keep = @($findings | Where-Object { -not ($_.Severity -eq 'medium' -and $_.Category -in 'cheat-name', 'cheat-string', 'cheat-behavior', 'obfuscation', 'behavior') })
        $findings.Clear()
        foreach ($k in $keep) { [void]$findings.Add($k) }
        $state.Hacks.Clear()
        $strongHacks = @(); $codeHacks = @()
    }

    $high = @($findings | Where-Object Severity -eq 'high').Count
    $med  = @($findings | Where-Object Severity -eq 'medium').Count
    $low  = @($findings | Where-Object Severity -eq 'low').Count
    $evMed = @($findings | Where-Object { $_.Severity -eq 'medium' -and $_.Category -in 'cheat-name', 'cheat-string', 'cheat-behavior' }).Count
    $structMed = @($findings | Where-Object { $_.Severity -eq 'medium' -and $_.Category -in 'obfuscation', 'bypass', 'native', 'behavior' }).Count
    $score = [math]::Min(100, ($high * 25) + ($med * 8) + ($low * 2))
    $hasMalware = (@($findings | Where-Object { $_.Severity -eq 'high' -and $_.Category -eq 'malware' }).Count -gt 0)

    $verdict = 'UNKNOWN'
    if ($hasMalware) { $verdict = 'MALWARE' }
    elseif ($policy -and $policy.Kind -eq 'banned') { $verdict = 'CHEAT (Banned Mod)' }
    elseif ($high -ge 1) { $verdict = 'CHEAT' }
    elseif ($policy) { $verdict = 'SUSPICIOUS (Suspect Mod)' }
    elseif ($evMed -ge 2 -or ($evMed -ge 1 -and ($codeHacks.Count -ge 1 -or $structMed -ge 1)) -or $structMed -ge 3) { $verdict = 'SUSPICIOUS' }
    elseif ($verified) { $verdict = 'VERIFIED' }
    if ($legit -and $verified -and $verdict -eq 'VERIFIED') { $verdict = 'VERIFIED (legit tool: ' + $legit + ')' }
    if ($verified -and $verdict -in 'CHEAT', 'MALWARE', 'SUSPICIOUS' -and -not $policy) {
        if (-not $legit -and $verdict -ne 'MALWARE' -and ($codeHacks.Count -ge 3 -or ($codeHacks.Count -ge 2 -and $combatBeh.Count -ge 2))) { $verdict = 'SUSPICIOUS (hack modules found in a Modrinth-hosted mod)' }
        else { $verdict = "$verdict (verified hash: probable false positive)" }
    }
    if ($verified -and $verdict -notlike 'SUSPICIOUS (hack modules*' -and -not $policy) { $state.Hacks.Clear() }

    if ($inactive -and ($verdict -like 'CHEAT*')) { $verdict = 'SUSPICIOUS (inactive copy)' }

    $profile = $null
    if ($prof -and -not $verified -and (Get-ModClass ([pscustomobject]@{ Verdict = $verdict })) -in 'CLEAN', 'SUSPICIOUS') { $profile = New-ModProfile $prof $meta $resNames $state }

    [pscustomobject]@{
        File         = $File.Name
        LocalPath    = $File.FullName
        Folder       = Hide-User $File.DirectoryName
        SizeKB       = [math]::Round($File.Length / 1KB)
        Sha1         = $sha1
        Sha256       = $Hashes.Sha256
        ModId        = if ($meta) { $meta.Id } else { $null }
        ModName      = if ($meta) { $meta.Name } else { $null }
        ModVersion   = if ($meta) { $meta.Version } else { $null }
        Loader       = if ($meta) { $meta.Loader } else { $null }
        Modrinth     = if ($verified) { $Modrinth[$sha1].Project } else { $null }
        Source       = $src.Url
        SourceTrust  = $src.Trust
        ModifiedUtc  = $File.LastWriteTimeUtc.ToString('o')
        CreatedUtc   = $File.CreationTimeUtc.ToString('o')
        AccessedUtc  = $File.LastAccessTimeUtc.ToString('o')
        Classes      = $classCount
        NestedJars   = $state.NestedJars
        DeepScanned  = (-not $skipped)
        Score        = $score
        Verdict      = $verdict
        Legit        = $legit
        Hacks        = @($state.Hacks.Values | Sort-Object Kind, Name)
        Profile      = $profile
        Findings     = @($findings | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; Category = $_.Category; Rule = $_.Rule; Detail = (Limit-Text (Hide-User $_.Detail) 300); Where = (Limit-Text (Hide-User $_.Where) 200) } })
    }
}

function Invoke-LooseFileScan([IO.FileInfo]$File, $Hashes) {
    $findings = New-Object System.Collections.Generic.List[object]
    $isPE = $false; $isDll = ($File.Extension -eq '.dll')
    try {
        $fs = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite, Delete')
        try { $h = New-Object byte[] 2; [void]$fs.Read($h, 0, 2); if ($h[0] -eq 0x4D -and $h[1] -eq 0x5A) { $isPE = $true } } finally { $fs.Dispose() }
    } catch {}
    if ($isPE -or $File.Extension -in '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.lnk') {
        $findings.Add((New-Finding 'high' 'bypass' 'Executable/script sitting in a mods folder' $File.Name $File.Name))
        if ($isPE -and $File.Length -le 32MB) { try { Test-DllBytes ([IO.File]::ReadAllBytes($File.FullName)) $File.Name $findings } catch {} }
    }
    foreach ($hv in $Hashes.Sha1, $Hashes.Sha256, $Hashes.Md5) {
        if ($hv -and $script:BadHashes.ContainsKey($hv)) { $findings.Add((New-Finding 'high' 'cheat-name' 'File hash is on the known-bad list' $script:BadHashes[$hv] $File.Name)) }
    }
    if ($findings.Count -eq 0) { return $null }
    [pscustomobject]@{
        File = $File.Name; LocalPath = $File.FullName; Folder = (Hide-User $File.DirectoryName); SizeKB = [math]::Round($File.Length / 1KB)
        Sha1 = $Hashes.Sha1; Sha256 = $Hashes.Sha256; ModId = $null; ModName = $null; ModVersion = $null; Loader = $null
        Modrinth = $null; Source = $null; SourceTrust = 'unknown'; ModifiedUtc = $File.LastWriteTimeUtc.ToString('o')
        Classes = 0; NestedJars = 0; DeepScanned = $true; Score = 75; Verdict = 'CHEAT'; Hacks = @()
        Findings = @($findings | ForEach-Object { [pscustomobject]@{ Severity = $_.Severity; Category = $_.Category; Rule = $_.Rule; Detail = (Limit-Text (Hide-User $_.Detail) 300); Where = (Limit-Text (Hide-User $_.Where) 200) } })
    }
}

function Get-McJavaProcesses {
    try {
        Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction Stop |
            Where-Object { $_.CommandLine -match '(?i)minecraft|net\.minecraft|fabric|forge|quilt|neoforge|lunar|feather|badlion|labymod|knot|launchwrapper|cpw\.mods' }
    } catch { @() }
}

$script:StaticModFolders = $null
function Get-StaticModFolders {
    if ($null -ne $script:StaticModFolders) { return $script:StaticModFolders }
    $roots = New-Object System.Collections.Generic.List[string]
    $searchDirs = New-Object System.Collections.Generic.List[string]
    $bases = New-Object System.Collections.Generic.List[string]
    foreach ($b in $env:APPDATA, $env:LOCALAPPDATA, $env:USERPROFILE, (Join-Path ([string]$env:USERPROFILE) 'Documents'), (Join-Path ([string]$env:USERPROFILE) 'Desktop'), (Join-Path ([string]$env:USERPROFILE) 'Downloads'), (Join-Path ([string]$env:USERPROFILE) 'Games')) { if ($b) { $bases.Add($b) } }
    if ($env:APPDATA) { $roots.Add((Join-Path $env:APPDATA '.minecraft\mods')) }
    $launchers = 'PrismLauncher', 'MultiMC', 'PolyMC', 'UltimMC', 'FjordLauncher', 'ElyPrismLauncher', 'ATLauncher', 'gdlauncher_next', 'gdlauncher_carbon', 'GDLauncher',
                 'ModrinthApp', 'com.modrinth.theseus', 'curseforge\minecraft\Instances', 'FTBApp', '.ftba', '.technic', 'TechnicLauncher', '.tlauncher', 'TLauncher',
                 '.hmcl', 'HMCL', 'xmcl', '.xmcl', 'SKLauncher', '.sklauncher', '.feather', '.lunarclient', '.badlion', 'Badlion Client', '.norisk', 'NoRiskClient',
                 '.salwyrr', 'Salwyrr', '.minecraft\versions', '.minecraft\labymod-neo', 'LabyMod'
    foreach ($base in $bases) { foreach ($launcher in $launchers) { $searchDirs.Add((Join-Path $base $launcher)) } }
    $nameRx = '(?i)^(\.?minecraft|prism|multimc|polymc|ultimmc|fjord|atlauncher|gdlauncher|modrinth|curseforge|ftb|technic|tlauncher|hmcl|xmcl|sklauncher|lunar|feather|badlion|labymod|norisk|salwyrr)|^(mc|games?|launchers?|minecraft[ _-]?(instances|launchers?|stuff)?)$'
    $tops = New-Object System.Collections.Generic.List[string]
    try { foreach ($d in [IO.DriveInfo]::GetDrives()) { if ($d.DriveType -eq 'Fixed' -and $d.IsReady) { $tops.Add($d.RootDirectory.FullName) } } } catch {}
    foreach ($b in (Join-Path ([string]$env:USERPROFILE) 'Desktop'), (Join-Path ([string]$env:USERPROFILE) 'Documents'), (Join-Path ([string]$env:USERPROFILE) 'Downloads'), $env:ProgramFiles, ${env:ProgramFiles(x86)}) { if ($b) { $tops.Add($b) } }
    foreach ($t in $tops) {
        if (-not (Test-Path -LiteralPath $t)) { continue }
        foreach ($d1 in @(Get-ChildItem -LiteralPath $t -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $nameRx -and $_.Name -notmatch '(?i)^(Windows|Program|ProgramData|\$)' })) {
            $searchDirs.Add($d1.FullName)
        }
    }
    foreach ($proc in @(Get-McJavaProcesses)) {
        try {
            $lp = Get-LauncherFromProcess $proc
            if ($lp.Dir) { $searchDirs.Add($lp.Dir); $searchDirs.Add((Split-Path -Parent $lp.Dir)) }
            $cl = [string]$proc.CommandLine
            foreach ($m in [regex]::Matches($cl, '(?i)([A-Z]:\\[^";=]*?\\(?:instances|profiles|modpacks)\\[^\\";]+)')) { $searchDirs.Add($m.Groups[1].Value) }
        } catch {}
    }
    $seen = @{}
    foreach ($sd in $searchDirs) {
        if (-not $sd) { continue }
        $k = $sd.ToLower().TrimEnd('\')
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        if (-not (Test-Path -LiteralPath $sd)) { continue }
        foreach ($dir in @(Get-ChildItem -LiteralPath $sd -Directory -Recurse -Depth 5 -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -in 'mods', 'user-mods' -and $_.FullName -notmatch '(?i)\\(assets|libraries|node_modules|\.git|cache|resourcepacks|shaderpacks|saves|screenshots|META-INF)\\' } | Select-Object -First 300)) {
            $hasJar = @(Get-ChildItem -LiteralPath $dir.FullName -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)\.jar(\.[a-z0-9_-]{1,12})?$' } | Select-Object -First 1).Count -gt 0
            $isDefault = $dir.FullName -match '(?i)\\\.minecraft\\mods$'
            if ($hasJar -or $isDefault) { $roots.Add($dir.FullName) }
        }
    }
    $script:StaticModFolders = @($roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | ForEach-Object { (Resolve-Path -LiteralPath $_).Path } | Select-Object -Unique)
    return $script:StaticModFolders
}

function Test-FileLocked([string]$Path) {
    try { $fs = [IO.File]::Open($Path, 'Open', 'Read', 'None'); $fs.Dispose(); return $false } catch [IO.IOException] { return $true } catch { return $false }
}

function Find-LiveGameDir($StartUtc) {
    $locked = New-Object System.Collections.Generic.List[object]
    foreach ($md in @(Get-StaticModFolders)) {
        $gd = Split-Path -Parent $md
        $lp = Join-Path $gd 'logs\latest.log'
        $hasLog = Test-Path -LiteralPath $lp
        $isLocked = $false
        if ($hasLog) { $isLocked = Test-FileLocked $lp }
        if (-not $isLocked) {
            foreach ($jf in @(Get-ChildItem -LiteralPath $md -File -Filter '*.jar' -ErrorAction SilentlyContinue | Select-Object -First 4)) { if (Test-FileLocked $jf.FullName) { $isLocked = $true; break } }
        }
        if (-not $isLocked) { continue }
        $fi = $null
        if ($hasLog) { $fi = Get-Item -LiteralPath $lp -ErrorAction SilentlyContinue }
        if ($fi) { $locked.Add([pscustomobject]@{ Dir = $gd; Created = $fi.CreationTimeUtc; Written = $fi.LastWriteTimeUtc }) }
        else { $locked.Add([pscustomobject]@{ Dir = $gd; Created = $null; Written = (Get-Date).ToUniversalTime() }) }
    }
    if ($locked.Count -eq 0) { return $null }
    if ($locked.Count -eq 1 -or -not $StartUtc) { return $locked[0].Dir }
    $best = $null; $bestGap = [double]::MaxValue
    foreach ($c in $locked) {
        if ($c.Written -lt $StartUtc.AddMinutes(-1)) { continue }
        if (-not $c.Created) { if (-not $best) { $best = $c.Dir }; continue }
        $gap = [math]::Abs(($c.Created - $StartUtc).TotalSeconds)
        if ($gap -lt $bestGap) { $bestGap = $gap; $best = $c.Dir }
    }
    return $best
}

function Find-ModFolders {
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($sm in @(Get-StaticModFolders)) { $roots.Add($sm) }
    foreach ($ri in @(Get-RunningInstances)) { if ($ri.ModsDir) { $roots.Add($ri.ModsDir) } }
    foreach ($m in $ModPath) { if ($m) { $roots.Add($m) } }

    $roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        ForEach-Object { (Resolve-Path -LiteralPath $_).Path } | Select-Object -Unique
}

$script:LastRunFile = $null
if ($env:LOCALAPPDATA) { $script:LastRunFile = Join-Path (Join-Path $env:LOCALAPPDATA 'CactusScan') 'lastrun.json' }
$script:PrevRun = $null
$script:Instances = @()
$script:TargetInstance = $null
$script:UsernameCheck = $null

function Get-CmdArg([string]$Cmd, [string]$Name) {
    if (-not $Cmd) { return $null }
    $m = [regex]::Match($Cmd, '(?i)(?:^|\s)--' + [regex]::Escape($Name) + '(?:\s+|=)(?:"([^"]*)"|(\S+))')
    if (-not $m.Success) { return $null }
    if ($m.Groups[1].Success) { return $m.Groups[1].Value }
    return $m.Groups[2].Value
}

function Get-LauncherInfo([string]$Path) {
    $p = [string]$Path
    if (-not $p) { return [pscustomobject]@{ Launcher = 'Unknown launcher'; Instance = 'unknown' } }
    $rules = @(
        @('Prism Launcher', '(?i)\\PrismLauncher\\instances\\([^\\]+)'),
        @('Fjord Launcher', '(?i)\\FjordLauncher\\instances\\([^\\]+)'),
        @('ElyPrism', '(?i)\\ElyPrismLauncher\\instances\\([^\\]+)'),
        @('MultiMC', '(?i)\\MultiMC[^\\]*\\instances\\([^\\]+)'),
        @('UltimMC', '(?i)\\UltimMC[^\\]*\\instances\\([^\\]+)'),
        @('PolyMC', '(?i)\\PolyMC[^\\]*\\instances\\([^\\]+)'),
        @('Modrinth App', '(?i)\\(?:ModrinthApp|com\.modrinth\.theseus)\\profiles\\([^\\]+)'),
        @('CurseForge', '(?i)\\curseforge\\minecraft\\Instances\\([^\\]+)'),
        @('ATLauncher', '(?i)\\ATLauncher\\instances\\([^\\]+)'),
        @('GDLauncher', '(?i)\\gdlauncher[^\\]*\\(?:data\\)?instances\\([^\\]+)'),
        @('FTB App', '(?i)\\(?:FTBApp|\.ftba)\\instances\\([^\\]+)'),
        @('X Minecraft Launcher', '(?i)\\\.?xmcl\\instances\\([^\\]+)'),
        @('Technic', '(?i)\\\.?technic\\modpacks\\([^\\]+)'),
        @('TLauncher', '(?i)\\\.?tlauncher\\.*?(?:versions|instances)\\([^\\]+)'),
        @('TLauncher', '(?i)\\\.?tlauncher(\\|$)'),
        @('HMCL', '(?i)\\\.?hmcl\\.*?versions\\([^\\]+)'),
        @('SKLauncher', '(?i)\\\.?sklauncher(\\|$)'),
        @('Lunar Client', '(?i)\\\.lunarclient\\.*?(?:profiles|multiver)\\([^\\]+)'),
        @('Lunar Client', '(?i)\\\.lunarclient(\\|$)'),
        @('Feather Client', '(?i)\\\.feather\\.*?(?:user-mods|mods)\\([^\\]+)'),
        @('Feather Client', '(?i)\\\.feather(\\|$)'),
        @('Badlion Client', '(?i)\\\.?badlion'),
        @('LabyMod', '(?i)\\labymod-neo\\(?:fabric\\)?([^\\]+)'),
        @('NoRisk Client', '(?i)\\\.?norisk'),
        @('Salwyrr', '(?i)\\\.?salwyrr')
    )
    $cur = $p.TrimEnd('\')
    $leaf = Split-Path -Leaf $cur
    for ($n = 0; $n -lt 2 -and $leaf -match '^(\.?minecraft|mods|user-mods)$'; $n++) {
        $cur = Split-Path -Parent $cur
        if (-not $cur) { break }
        $leaf = Split-Path -Leaf $cur
    }
    foreach ($r in $rules) {
        $m = [regex]::Match($p, $r[1])
        if ($m.Success) {
            $inst = $leaf
            if ($m.Groups.Count -gt 1 -and $m.Groups[1].Success -and $m.Groups[1].Value -and $m.Groups[1].Value -ne '\') { $inst = $m.Groups[1].Value }
            return [pscustomobject]@{ Launcher = $r[0]; Instance = $inst }
        }
    }
    $vm = [regex]::Match($p, '(?i)\\\.minecraft\\versions\\([^\\]+)')
    if ($vm.Success) { return [pscustomobject]@{ Launcher = 'Minecraft (version-isolated folder)'; Instance = $vm.Groups[1].Value } }
    $gm = [regex]::Match($p, '(?i)\\([^\\]+)\\(?:instances|profiles|modpacks)\\([^\\]+)')
    if ($gm.Success) {
        $ln = ($gm.Groups[1].Value -replace '^\.', '')
        return [pscustomobject]@{ Launcher = $ln; Instance = $gm.Groups[2].Value }
    }
    if ($p -match '(?i)\\\.minecraft(\\|$)') { return [pscustomobject]@{ Launcher = 'Minecraft Launcher'; Instance = 'default (.minecraft)' } }
    return [pscustomobject]@{ Launcher = 'Custom folder'; Instance = $leaf }
}

function Get-LauncherFromProcess($Proc) {
    $map = @(
        @('(?i)prism', 'Prism Launcher'), @('(?i)multimc', 'MultiMC'), @('(?i)polymc', 'PolyMC'), @('(?i)ultimmc', 'UltimMC'), @('(?i)fjord', 'Fjord Launcher'),
        @('(?i)modrinth', 'Modrinth App'), @('(?i)curseforge|overwolf', 'CurseForge'), @('(?i)atlauncher', 'ATLauncher'), @('(?i)gdlauncher', 'GDLauncher'),
        @('(?i)ftb', 'FTB App'), @('(?i)technic', 'Technic'), @('(?i)tlauncher|legacy', 'TLauncher'), @('(?i)hmcl', 'HMCL'), @('(?i)sklauncher', 'SKLauncher'),
        @('(?i)lunar', 'Lunar Client'), @('(?i)feather', 'Feather Client'), @('(?i)badlion', 'Badlion Client'), @('(?i)labymod', 'LabyMod'), @('(?i)xmcl', 'X Minecraft Launcher'),
        @('(?i)minecraftlauncher|minecraft launcher|minecraft\.exe', 'Minecraft Launcher')
    )
    $res = [pscustomobject]@{ Name = $null; Dir = $null }
    try {
        $pp = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [int]$Proc.ParentProcessId) -ErrorAction Stop
        foreach ($cand in @($pp, $null)) {
            $txt = ''
            if ($cand) { $txt = [string]$cand.Name + ' ' + [string]$cand.ExecutablePath + ' ' + [string]$cand.CommandLine; if ($cand.ExecutablePath) { $res.Dir = Split-Path -Parent ([string]$cand.ExecutablePath) } }
            else { $txt = [string]$Proc.ExecutablePath + ' ' + [string]$Proc.CommandLine }
            foreach ($m in $map) { if ($txt -match $m[0]) { $res.Name = $m[1]; return $res } }
        }
    } catch {
        $txt = [string]$Proc.ExecutablePath + ' ' + [string]$Proc.CommandLine
        foreach ($m in $map) { if ($txt -match $m[0]) { $res.Name = $m[1]; return $res } }
    }
    return $res
}

function Get-RunningInstances {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in @(Get-McJavaProcesses)) {
        $cmd = [string]$p.CommandLine
        if (-not $cmd) { continue }
        $user = Get-CmdArg $cmd 'username'
        $uuid = Get-CmdArg $cmd 'uuid'
        $ver = Get-CmdArg $cmd 'version'
        $gd = Get-CmdArg $cmd 'gameDir'
        if (-not $gd -and $cmd -match '--gameDir\s+"?([^"\s][^"]*?)"?(\s+--|\s*$)') { $gd = $Matches[1] }
        if (-not $gd) {
            $td = [regex]::Match($cmd, '(?i)-Dminecraft\.applet\.TargetDirectory=("[^"]+"|\S+)')
            if ($td.Success) { $gd = $td.Groups[1].Value.Trim('"') }
        }
        if (-not $gd) {
            $lpm = [regex]::Match($cmd, '(?i)-Djava\.library\.path=("[^"]+"|\S+)')
            if ($lpm.Success) {
                $lpv = $lpm.Groups[1].Value.Trim('"')
                $ib = [regex]::Match($lpv, '(?i)^(.*\\(?:instances|profiles)\\[^\\]+)\\natives')
                if ($ib.Success) {
                    foreach ($sub in 'minecraft', '.minecraft') { $cand = Join-Path $ib.Groups[1].Value $sub; if (Test-Path -LiteralPath $cand) { $gd = $cand; break } }
                }
            }
        }
        if (-not $gd) {
            $stl = $null
            try { $stl = $p.CreationDate.ToUniversalTime() } catch {}
            $gd = Find-LiveGameDir $stl
        }
        if (-not $gd -and $env:APPDATA -and $cmd -match '(?i)\\\.minecraft\\') { $gd = Join-Path $env:APPDATA '.minecraft' }
        if (-not $user -and $gd) {
            $lgp = Join-Path $gd 'logs\latest.log'
            if (Test-Path -LiteralPath $lgp) {
                $ltx = [string](Read-TextFileSafe $lgp)
                $um = [regex]::Match($ltx, 'Setting user:\s*(\S+)')
                if ($um.Success) { $user = $um.Groups[1].Value }
            }
        }
        $loader = ''
        if ($cmd -match '(?i)neoforge') { $loader = 'NeoForge' }
        elseif ($cmd -match '(?i)quilt') { $loader = 'Quilt' }
        elseif ($cmd -match '(?i)fabric') { $loader = 'Fabric' }
        elseif ($cmd -match '(?i)forge') { $loader = 'Forge' }
        $md = $null
        if ($gd) {
            $c = Join-Path $gd 'mods'
            if (Test-Path -LiteralPath $c) { try { $md = (Resolve-Path -LiteralPath $c -ErrorAction Stop).Path } catch { $md = $c } }
        }
        $st = $null
        try { $st = $p.CreationDate.ToUniversalTime() } catch {}
        $li = Get-LauncherInfo $gd
        if ($li.Launcher -in 'Unknown launcher', 'Custom folder', 'Minecraft Launcher') {
            $lp = Get-LauncherFromProcess $p
            if ($lp.Name -and ($li.Launcher -ne 'Minecraft Launcher' -or $lp.Name -ne 'Minecraft Launcher')) { $li = [pscustomobject]@{ Launcher = $lp.Name; Instance = $li.Instance } }
        }
        [void]$out.Add([pscustomobject]@{
            Pid = [int]$p.ProcessId; Process = [string]$p.Name; Username = $user; Uuid = $uuid; Version = $ver; Loader = $loader
            GameDir = $gd; ModsDir = $md; Launcher = $li.Launcher; Instance = $li.Instance; StartedUtc = $st
        })
    }
    return $out.ToArray()
}

function Get-FolderLabel([string]$Folder, $Instances) {
    $f = ([string]$Folder).TrimEnd('\')
    foreach ($i in @($Instances | Where-Object { $_ })) {
        foreach ($root in @($i.ModsDir, $i.GameDir)) {
            if (-not $root) { continue }
            $r = ([string]$root).TrimEnd('\')
            if ($f.Equals($r, [StringComparison]::OrdinalIgnoreCase) -or $f.StartsWith($r + '\', [StringComparison]::OrdinalIgnoreCase)) {
                return [pscustomobject]@{ Running = $true; Text = ('{0} / {1}' -f $i.Launcher, $i.Instance); Instance = $i }
            }
        }
    }
    $li = Get-LauncherInfo $f
    return [pscustomobject]@{ Running = $false; Text = ('{0} / {1}' -f $li.Launcher, $li.Instance); Instance = $null }
}

function Get-HttpStatus($ErrorRecord) {
    try { return [int]$ErrorRecord.Exception.Response.StatusCode } catch { return 0 }
}

function Test-MojangUsername([string]$Name) {
    if ($NoOnline) { return [pscustomobject]@{ Status = 'unknown'; Name = $null; Id = $null } }
    $enc = [uri]::EscapeDataString($Name)
    $urls = @(('https://api.mojang.com/users/profiles/minecraft/' + $enc), ('https://api.minecraftservices.com/minecraft/profile/lookup/name/' + $enc))
    $missing = 0
    foreach ($u in $urls) {
        try {
            $r = Invoke-RestMethod -Method Get -Uri $u -TimeoutSec 8 -ErrorAction Stop
            if ($r -and $r.name) { return [pscustomobject]@{ Status = 'exists'; Name = [string]$r.name; Id = [string]$r.id } }
            $missing++
        } catch {
            $code = Get-HttpStatus $_
            if ($code -eq 404 -or $code -eq 204) { $missing++ }
        }
    }
    if ($missing -ge 2) { return [pscustomobject]@{ Status = 'missing'; Name = $null; Id = $null } }
    return [pscustomobject]@{ Status = 'unknown'; Name = $null; Id = $null }
}

function Get-MaskedName([string]$Name) {
    if (-not $Name) { return '' }
    if ($Name.Length -le 2) { return ($Name.Substring(0, 1) + '*') }
    return ($Name.Substring(0, 1) + ('*' * ($Name.Length - 2)) + $Name.Substring($Name.Length - 1))
}

function Resolve-UsernameClaim([string]$Entered, $Accounts, $Instances) {
    $name = ([string]$Entered).Trim()
    $r = [pscustomobject]@{ Ok = $false; Message = ''; Account = $null; Instance = $null; Method = ''; Mojang = ''; UuidMatch = $null }
    if ($name -notmatch '^[A-Za-z0-9_]{1,16}$') {
        $r.Message = ('"{0}" is not a valid Minecraft username (1-16 letters, numbers or underscores).' -f (Limit-Text $name 24))
        return $r
    }
    $accts = @($Accounts | Where-Object { $_ })
    $local = Match-MinecraftAccount $accts $name
    $running = @($Instances | Where-Object { $_ -and $_.Username })
    if ($running.Count -gt 0) {
        $hit = @($running | Where-Object { $_.Username.Equals($name, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
        if ($hit.Count -eq 0) {
            $masked = (@($running | ForEach-Object { Get-MaskedName $_.Username } | Select-Object -Unique) -join ', ')
            $r.Message = ('"{0}" is not the account of the Minecraft that is running right now (it is logged in as {1}). Enter the username you are playing on.' -f $name, $masked)
            return $r
        }
        $inst = $hit[0]
        $acct = $local
        if (-not $acct) { $acct = [pscustomobject]@{ Name = $inst.Username; YggUserName = $null; Id = $inst.Uuid; Active = $true; Source = 'running-instance' } }
        if ($local -and $local.Id -and $inst.Uuid) {
            $r.UuidMatch = (([string]$local.Id -replace '-', '').ToLower() -eq ([string]$inst.Uuid -replace '-', '').ToLower())
        }
        $r.Ok = $true; $r.Account = $acct; $r.Instance = $inst; $r.Method = 'running-instance'; $r.Mojang = 'skipped'
        return $r
    }
    if ($local) {
        $r.Ok = $true; $r.Account = $local; $r.Method = 'launcher-account'; $r.Mojang = 'skipped'
        return $r
    }
    if ($accts.Count -gt 0) {
        $r.Message = ('no launcher account named "{0}" exists on this PC ({1} account(s) found). Enter the username you really play on.' -f $name, $accts.Count)
        return $r
    }
    $mj = Test-MojangUsername $name
    $r.Mojang = $mj.Status
    if ($mj.Status -eq 'missing') {
        $r.Message = ('the username "{0}" does not exist on Mojang and no launcher account was found on this PC.' -f $name)
        return $r
    }
    $nm = $name; $id = $null
    if ($mj.Status -eq 'exists') { $nm = $mj.Name; $id = $mj.Id }
    $src = 'user-input'; $method = 'unverified'
    if ($mj.Status -eq 'exists') { $src = 'mojang'; $method = 'mojang' }
    $r.Ok = $true; $r.Method = $method
    $r.Account = [pscustomobject]@{ Name = $nm; YggUserName = $null; Id = $id; Active = $true; Source = $src }
    return $r
}

function Select-MinecraftAccount([string]$TargetUsername, $Instances) {
    $accounts = @(Get-AllMinecraftAccounts)
    $script:UsernameCheck = [ordered]@{ method = ''; attempts = 0; failures = 0; mojang = ''; uuidMatch = $null }
    $entered = $TargetUsername
    $tries = 0
    while ($tries -lt 3) {
        if ([string]::IsNullOrWhiteSpace($entered)) {
            try { $entered = Read-Host '  Enter your Minecraft username' } catch { break }
        }
        $tries++
        $script:UsernameCheck.attempts = $tries
        $res = Resolve-UsernameClaim $entered $accounts $Instances
        if ($res.Ok) {
            $script:UsernameCheck.method = $res.Method
            $script:UsernameCheck.mojang = $res.Mojang
            $script:UsernameCheck.uuidMatch = $res.UuidMatch
            $script:UsernameCheck.failures = $tries - 1
            return $res
        }
        $script:UsernameCheck.failures = $tries
        Write-Host ('  WRONG USERNAME: ' + $res.Message) -ForegroundColor Red
        if ($tries -lt 3) { Write-Host ('  Try again ({0} attempt(s) left).' -f (3 - $tries)) -ForegroundColor Yellow }
        $entered = $null
    }
    return $null
}

function ConvertTo-RunTime($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try { return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } catch { return $null }
}

function Format-Ago([datetime]$Utc) {
    $s = ((Get-Date).ToUniversalTime() - $Utc).TotalSeconds
    if ($s -lt 90) { return 'just now' }
    $n = 0; $u = 'minute'
    if ($s -lt 3600) { $n = [int][math]::Floor($s / 60) }
    elseif ($s -lt 86400) { $n = [int][math]::Floor($s / 3600); $u = 'hour' }
    else { $n = [int][math]::Floor($s / 86400); $u = 'day' }
    if ($n -ne 1) { $u += 's' }
    return ('{0} {1} ago' -f $n, $u)
}

function Read-LastRun {
    try {
        if ($script:LastRunFile -and (Test-Path -LiteralPath $script:LastRunFile)) {
            return (Get-Content -LiteralPath $script:LastRunFile -Raw -ErrorAction Stop | ConvertFrom-Json)
        }
    } catch {}
    return $null
}

function Write-LastRun($Summary, [string]$Name) {
    if (-not $script:LastRunFile) { return }
    try {
        $dir = Split-Path -Parent $script:LastRunFile
        if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        $n = 1
        if ($script:PrevRun -and $script:PrevRun.runs) { $n = [int]$script:PrevRun.runs + 1 }
        $inst = ''
        if ($script:TargetInstance) { $inst = ('{0} / {1}' -f $script:TargetInstance.Launcher, $script:TargetInstance.Instance) }
        $o = [ordered]@{
            timeUtc = (Get-Date).ToUniversalTime().ToString('o'); username = $Name; verdict = [string]$Summary.verdict
            category = [string]$Summary.category; score = [int]$Summary.threatScore; runs = $n; instance = $inst
        }
        [IO.File]::WriteAllText($script:LastRunFile, ($o | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    } catch {}
}

function Show-LastRun($Prev) {
    $t = $null
    if ($Prev) { $t = ConvertTo-RunTime $Prev.timeUtc }
    if (-not $t) { Write-Host '  Last scan : never (first scan on this PC)' -ForegroundColor DarkGray; return }
    $who = ''
    if ($Prev.username) { $who = ', as ' + $Prev.username }
    Write-Host ('  Last scan : {0} ({1}) - verdict {2}, score {3}/100{4}' -f $t.ToLocalTime().ToString('yyyy-MM-dd HH:mm'), (Format-Ago $t), $Prev.verdict, $Prev.score, $who) -ForegroundColor Cyan
}

function Show-ScanTarget($Instances, $Res) {
    Write-Section 'SCAN TARGET'
    $acct = $Res.Account
    $how = 'could not be checked online, not verified'
    if ($Res.Method -eq 'running-instance') { $how = 'verified: matches the account of the running Minecraft' }
    elseif ($Res.Method -eq 'launcher-account') { $how = 'verified: found in the launcher accounts on this PC' }
    elseif ($Res.Method -eq 'mojang') { $how = 'verified: exists on Mojang (no launcher account on this PC to compare)' }
    $col = 'Green'
    if ($Res.Method -eq 'unverified') { $col = 'Yellow' }
    Write-Host ('  Username   : {0}  ({1})' -f $acct.Name, $how) -ForegroundColor $col
    if ($Res.UuidMatch -eq $false) { Write-Host '  WARNING    : the running game UUID does not match the launcher account with that name' -ForegroundColor Yellow }
    $list = @($Instances | Where-Object { $_ })
    if ($list.Count -eq 0) {
        Write-Host '  Minecraft  : not running - scanning every mods folder found on this PC' -ForegroundColor DarkGray
        return
    }
    foreach ($i in $list) {
        $isTarget = ($Res.Instance -and $i.Pid -eq $Res.Instance.Pid)
        $tag = 'also running, not the verified account'
        $tcol = 'DarkGray'
        if ($isTarget) { $tag = 'THIS INSTANCE IS BEING SCANNED'; $tcol = 'Green' }
        $ver = (('{0} {1}' -f $i.Loader, $i.Version).Trim())
        Write-Host ''
        Write-Host ('  Minecraft  : RUNNING  PID {0}  {1}   [{2}]' -f $i.Pid, $ver, $tag) -ForegroundColor $tcol
        Write-Host ('  Launcher   : {0}' -f $i.Launcher) -ForegroundColor Gray
        Write-Host ('  Instance   : {0}' -f $i.Instance) -ForegroundColor Gray
        if ($i.Username) { Write-Host ('  Logged in  : {0}' -f $i.Username) -ForegroundColor Gray }
        if ($i.GameDir) { Write-Host ('  Location   : {0}' -f (Hide-User $i.GameDir)) -ForegroundColor Gray }
        if ($i.ModsDir) {
            $cnt = @(Get-ChildItem -LiteralPath $i.ModsDir -File -Force -ErrorAction SilentlyContinue).Count
            Write-Host ('  Mods folder: {0}  ({1} file(s))' -f (Hide-User $i.ModsDir), $cnt) -ForegroundColor Gray
        } else {
            Write-Host '  Mods folder: not found for this instance' -ForegroundColor DarkYellow
        }
        if ($i.StartedUtc) { Write-Host ('  Started    : {0}' -f (Format-When $i.StartedUtc.ToString('o'))) -ForegroundColor Gray }
    }
}

function Read-TextFileSafe([string]$Path, [long]$MaxLen = 30MB) {
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.Length -gt $MaxLen) { return $null }
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
        try {
            if ($Path -like '*.gz') { $gz = New-Object IO.Compression.GZipStream($fs, [IO.Compression.CompressionMode]::Decompress); $sr = New-Object IO.StreamReader($gz) }
            else { $sr = New-Object IO.StreamReader($fs) }
            try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
        } finally { $fs.Dispose() }
    } catch { return $null }
}

function Get-AllMinecraftAccounts {
    $found = New-Object System.Collections.Generic.List[object]
    $searchPaths = New-Object System.Collections.Generic.List[string]
    if ($env:APPDATA) {
        $searchPaths.Add((Join-Path $env:APPDATA '.minecraft\launcher_accounts.json'))
        $searchPaths.Add((Join-Path $env:APPDATA '.minecraft\launcher_profiles.json'))
        $searchPaths.Add((Join-Path $env:APPDATA 'PrismLauncher\accounts.json'))
        $searchPaths.Add((Join-Path $env:APPDATA 'MultiMC\accounts.json'))
        $searchPaths.Add((Join-Path $env:APPDATA 'ModrinthApp\accounts.json'))
        $searchPaths.Add((Join-Path $env:APPDATA 'badlionclient\accounts.json'))
        $searchPaths.Add((Join-Path $env:APPDATA '.feather\accounts.json'))
    }
    if ($env:USERPROFILE) {
        $searchPaths.Add((Join-Path $env:USERPROFILE '.lunarclient\offline\multiver\accounts.json'))
        $searchPaths.Add((Join-Path $env:USERPROFILE '.lunarclient\accounts.json'))
        $searchPaths.Add((Join-Path $env:USERPROFILE '.lunarclient\settings\game\accounts.json'))
    }

    foreach ($path in $searchPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $text = Read-TextFileSafe $path 4MB
        if (-not $text) { continue }
        try {
            $doc = $text | ConvertFrom-Json -ErrorAction Stop
        } catch { continue }

        $srcLabel = (Split-Path -Leaf (Split-Path -Parent $path)) + '/' + (Split-Path -Leaf $path)

        if ($doc.accounts -is [System.Collections.IEnumerable] -and $doc.accounts -isnot [string] -and $doc.accounts -isnot [hashtable]) {
            foreach ($acc in @($doc.accounts)) {
                $pName = if ($acc.profile -and $acc.profile.name) { [string]$acc.profile.name } else { '' }
                $yggName = if ($acc.ygg -and $acc.ygg.extra -and $acc.ygg.extra.userName) { [string]$acc.ygg.extra.userName } else { '' }
                $profileId = if ($acc.profile -and $acc.profile.id) { [string]$acc.profile.id } else { '' }
                $isActive = [bool]($acc.active -or $acc.selected)

                $validName = if ($pName -match '^[A-Za-z0-9_]{1,16}$') { $pName } elseif ($yggName -match '^[A-Za-z0-9_]{1,16}$') { $yggName } else { '' }
                if ($validName) {
                    [void]$found.Add([pscustomobject]@{
                        Name = $validName
                        YggUserName = $yggName
                        Id = $profileId
                        Active = $isActive
                        Source = $srcLabel
                    })
                }
            }
        }

        $activeId = [string]$doc.activeAccountLocalId
        foreach ($container in @($doc.accounts, $doc.authenticationDatabase)) {
            if (-not $container -or -not $container.PSObject) { continue }
            if ($container -is [System.Collections.IEnumerable] -and $container -isnot [string] -and $container -isnot [hashtable]) { continue }
            foreach ($entry in $container.PSObject.Properties) {
                $acc = $entry.Value
                $profiles = @($acc.minecraftProfile, $acc.profile)
                if ($acc.profiles -and $acc.profiles.PSObject) { $profiles += @($acc.profiles.PSObject.Properties | ForEach-Object { $_.Value }) }
                $yggName = if ($acc.ygg -and $acc.ygg.extra -and $acc.ygg.extra.userName) { [string]$acc.ygg.extra.userName } else { '' }

                foreach ($profile in $profiles) {
                    $name = if ($profile -and $profile.name) { [string]$profile.name } elseif ($profile -and $profile.displayName) { [string]$profile.displayName } else { '' }
                    if ($name -notmatch '^[A-Za-z0-9_]{1,16}$') {
                        if ($yggName -match '^[A-Za-z0-9_]{1,16}$') { $name = $yggName } else { continue }
                    }
                    $id = if ($profile -and $profile.id) { [string]$profile.id } else { '' }
                    [void]$found.Add([pscustomobject]@{
                        Name = $name
                        YggUserName = $yggName
                        Id = $id
                        Active = ($entry.Name -eq $activeId)
                        Source = $srcLabel
                    })
                }
            }
        }
    }

    $seen = @{}
    $result = @()
    foreach ($item in $found) {
        $k = $item.Name.ToLower()
        if (-not $seen.ContainsKey($k)) {
            $seen[$k] = $true
            $result += $item
        }
    }
    return $result
}

function Match-MinecraftAccount($AccountsList, [string]$EnteredUsername) {
    if (-not $EnteredUsername) { return $null }
    $clean = $EnteredUsername.Trim()
    foreach ($acc in $AccountsList) {
        if ($acc.Name -and $acc.Name.Equals($clean, [StringComparison]::OrdinalIgnoreCase)) {
            return $acc
        }
        if ($acc.YggUserName -and $acc.YggUserName.Equals($clean, [StringComparison]::OrdinalIgnoreCase)) {
            return $acc
        }
    }
    return $null
}

function Get-MinecraftAccountReport($SelectedAccount) {
    $all = @(Get-AllMinecraftAccounts)
    $curName = if ($SelectedAccount) { $SelectedAccount.Name } else { $null }
    $alts = @($all | Where-Object { $_.Name -and $_.Name -ne $curName } | ForEach-Object { $_.Name } | Select-Object -Unique)
    $profiles = @($all | ForEach-Object {
        [ordered]@{
            name   = $_.Name
            id     = $_.Id
            source = $_.Source
            active = ($_.Name -eq $curName)
        }
    })
    if ($SelectedAccount -and -not ($all | Where-Object { $_.Name -eq $curName })) {
        $profiles += [ordered]@{
            name   = $SelectedAccount.Name
            id     = $SelectedAccount.Id
            source = $SelectedAccount.Source
            active = $true
        }
    }
    return [ordered]@{
        currentAccountName = $curName
        alternateAccounts  = $alts
        profiles           = $profiles
    }
}

function Get-MinecraftAccountProfiles {
    return Get-MinecraftAccountReport $script:SelectedAccount
}

$script:VanillaKeyRx = New-Object Regex('^key\.(attack|use|forward|left|back|right|jump|sneak|sprint|drop|inventory|chat|playerlist|pickItem|command|socialInteractions|screenshot|togglePerspective|smoothCamera|fullscreen|spectatorOutlines|swapOffhand|saveToolbarActivator|loadToolbarActivator|advancements|hotbar\.[1-9]|stream\w+)$', 'Compiled')

function Add-Keybind([string]$Name, [string]$Key, [string]$Source, [string]$Confidence) {
    [void]$script:Keybinds.Add([pscustomobject]@{ Name = $Name; Key = $Key; Source = $Source; Confidence = $Confidence; Used = $false })
}

function Read-OptionsKeybinds([string]$GameDir) {
    $opt = Join-Path $GameDir 'options.txt'
    if (-not (Test-Path -LiteralPath $opt)) { return }
    foreach ($line in @(Get-Content -LiteralPath $opt -ErrorAction SilentlyContinue)) {
        if ($line -match '^key_(.+?):(\S+)\s*$') {
            $name = $Matches[1]; $val = $Matches[2]
            if ($script:VanillaKeyRx.IsMatch($name)) { continue }
            Add-Keybind $name (Convert-OptionKey $val) "options.txt ($(Split-Path -Leaf $GameDir))" 'exact'
        }
    }
}

function Read-ClientConfigs([string]$Dir) {
    $files = @(Get-ChildItem -LiteralPath $Dir -File -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.json', '.txt', '.cfg', '.conf', '.toml', '.properties', '.ini', '.yml', '.yaml' -and $_.Length -le 1MB } |
        Select-Object -First 40)
    $added = 0
    foreach ($f in $files) {
        if ($added -ge 60) { break }
        $t = Read-TextFileSafe $f.FullName 1MB
        if (-not $t) { continue }
        $src = "config: " + (Hide-User ($f.FullName.Substring([math]::Min($f.FullName.Length, $Dir.Length)).TrimStart('\')))
        foreach ($m in [regex]::Matches($t, '(?is)"([A-Za-z0-9_\- ]{3,32})"\s*:\s*\{[^{}]{0,400}?"(?:key|keybind|bind|hotkey|keycode)"\s*:\s*"?([A-Za-z0-9_.\-]{1,30})"?')) {
            Add-Keybind $m.Groups[1].Value (ConvertTo-KeyText $m.Groups[2].Value) $src 'config'; $added++
        }
        foreach ($m in [regex]::Matches($t, '"(key\.(?:keyboard|mouse)\.[a-z0-9._]+)"\s*:\s*"([^"]{1,120})"')) {
            Add-Keybind (Limit-Text $m.Groups[2].Value 60) (Convert-OptionKey $m.Groups[1].Value) $src 'config'; $added++
        }
        foreach ($m in [regex]::Matches($t, '(?im)^\s*([A-Za-z0-9_\-]{3,32})[._\-](?:key|bind|keybind|hotkey)\s*[:=]\s*"?([A-Za-z0-9_.\-]{1,24})"?')) {
            Add-Keybind $m.Groups[1].Value (ConvertTo-KeyText $m.Groups[2].Value) $src 'config'; $added++
        }
    }
}
function ConvertTo-KeyText([string]$v) {
    if ($v -match '^key\.') { return (Convert-OptionKey $v) }
    if ($v -match '^\d+$') { return (Format-KeyCode ([int]$v) 0 $null) }
    return $v
}

function Find-ClientTraces([string]$GameDir) {
    foreach ($dir in @(Get-ChildItem -LiteralPath $GameDir -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($ClientDirRx.IsMatch($dir.Name)) {
            Add-Sys 'high' 'game-artifact' 'Cheat client data folder in the game directory' $dir.FullName $dir.LastWriteTimeUtc 'game folder'
            Read-ClientConfigs $dir.FullName
        }
    }
    $cfg = Join-Path $GameDir 'config'
    if (Test-Path -LiteralPath $cfg) {
        foreach ($item in @(Get-ChildItem -LiteralPath $cfg -Force -ErrorAction SilentlyContinue | Select-Object -First 400)) {
            $n = $item.Name -replace '\.[A-Za-z0-9]+$', ''
            if ($ClientDirRx.IsMatch($n) -or $Rx.Clients.IsMatch($n)) {
                Add-Sys 'high' 'game-artifact' 'Cheat client config in the config folder' $item.FullName $item.LastWriteTimeUtc 'game folder'
                if ($item.PSIsContainer) { Read-ClientConfigs $item.FullName }
            }
        }
    }
    $vd = Join-Path $GameDir 'versions'
    if (Test-Path -LiteralPath $vd) {
        foreach ($v in @(Get-ChildItem -LiteralPath $vd -Directory -ErrorAction SilentlyContinue)) {
            if ($Rx.Clients.IsMatch($v.Name) -or $ClientDirRx.IsMatch($v.Name)) { Add-Sys 'high' 'game-artifact' 'Cheat client installed as a game version' $v.FullName $v.LastWriteTimeUtc 'versions folder' }
        }
    }
    $lp = Join-Path $GameDir 'launcher_profiles.json'
    if (Test-Path -LiteralPath $lp) {
        $t = Read-TextFileSafe $lp 4MB
        if ($t) {
            foreach ($m in [regex]::Matches($t, '"(?:name|lastVersionId)"\s*:\s*"([^"]+)"')) {
                if ($Rx.Clients.IsMatch($m.Groups[1].Value)) { Add-Sys 'high' 'game-artifact' 'Launcher profile/version named after a cheat client' $m.Groups[1].Value $null 'launcher_profiles.json' }
            }
        }
    }
}

$script:BuiltinModIds = 'minecraft|java|fabricloader|fabric-api|fabric|fabric_api|quilt_loader|quilted_fabric_api|mixinextras|forge|neoforge|fml|mcp|lwjgl|javafml|lowcodefml|minecraftforge'

function Scan-GameLogs([string]$GameDir, $KnownModIds) {
    $logs = New-Object System.Collections.Generic.List[string]
    $ld = Join-Path $GameDir 'logs'
    if (Test-Path -LiteralPath $ld) {
        foreach ($n in 'latest.log', 'debug.log') { $p = Join-Path $ld $n; if (Test-Path -LiteralPath $p) { $logs.Add($p) } }
        foreach ($g in @(Get-ChildItem -LiteralPath $ld -Filter '*.log.gz' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3)) { $logs.Add($g.FullName) }
    }
    $loaded = @{}
    foreach ($lf in $logs) {
        $t = Read-TextFileSafe $lf
        if (-not $t) { continue }
        $hits = @{}; $modHits = @{}; $inList = $false
        $isLatest = ($lf -like '*latest.log')
        if ($isLatest) {
            $lm = [regex]::Match($t, 'Loading \d+ mods?:')
            if ($lm.Success) {
                $nl = $t.IndexOf([char]10, $lm.Index)
                if ($nl -ge 0) {
                    $pos = $nl + 1
                    $cnt = 0
                    while ($pos -lt $t.Length -and $cnt -lt 5000) {
                        $e = $t.IndexOf([char]10, $pos)
                        if ($e -lt 0) { $e = $t.Length }
                        $ln = $t.Substring($pos, $e - $pos).TrimEnd([char]13)
                        if ($ln.StartsWith('[')) { break }
                        if ($ln -match '^\s+-\s+(\S+)\s+(\S+)') { $loaded[$Matches[1].ToLower()] = $Matches[2] }
                        $pos = $e + 1
                        $cnt++
                    }
                }
            }
        }
        $guard = 0
        $cm = $Rx.Clients.Match($t)
        while ($cm.Success -and $guard -lt 3000 -and $hits.Count -lt 4) {
            $guard++
            $hk = $cm.Value.ToLower()
            if (-not $hits.ContainsKey($hk)) {
                $ls = $t.LastIndexOf([char]10, $cm.Index) + 1
                $le = $t.IndexOf([char]10, $cm.Index)
                if ($le -lt 0) { $le = $t.Length }
                $ln = $t.Substring($ls, $le - $ls)
                if ($ln.IndexOf('[CHAT]', [StringComparison]::Ordinal) -lt 0) { $hits[$hk] = (Limit-Text $ln.TrimEnd([char]13) 140) }
            }
            $cm = $cm.NextMatch()
        }
        $guard = 0
        $mm = $Rx.Modules.Match($t)
        while ($mm.Success -and $guard -lt 3000 -and $modHits.Count -lt 40) {
            $guard++
            $mk = $mm.Value.ToLower()
            if (-not $modHits.ContainsKey($mk)) {
                $ls = $t.LastIndexOf([char]10, $mm.Index) + 1
                $le = $t.IndexOf([char]10, $mm.Index)
                if ($le -lt 0) { $le = $t.Length }
                if ($t.IndexOf('[CHAT]', $ls, $le - $ls, [StringComparison]::Ordinal) -lt 0) { $modHits[$mk] = $true }
            }
            $mm = $mm.NextMatch()
        }
        $fi = Get-Item -LiteralPath $lf -ErrorAction SilentlyContinue
        $ft = $null; if ($fi) { $ft = $fi.LastWriteTimeUtc }
        foreach ($k in $hits.Keys) { Add-Sys 'high' 'game-log' 'Game log mentions a cheat client' ("{0}: {1}" -f (Split-Path -Leaf $lf), $hits[$k]) $ft 'logs' }
        if ($modHits.Count -ge 3) { Add-Sys 'medium' 'game-log' 'Game log mentions several hack module names' ("{0}: {1}" -f (Split-Path -Leaf $lf), ((@($modHits.Keys) | Select-Object -First 8) -join ', ')) $ft 'logs' }
    }

    if ($loaded.Count -gt 0) {
        $gone = @()
        foreach ($id in $loaded.Keys) {
            if ($id -match "^($script:BuiltinModIds)$" -or $id -like 'fabric-*' -or $id -like 'fabric_*' -or $id -like 'quilt*' -or $id -like 'org_*') { continue }
            if (-not (Test-KnownLoadedId $id $KnownModIds)) { $gone += $id }
        }
        if ($gone.Count -gt 0) {
            $bad = @($gone | Where-Object { $Rx.Clients.IsMatch($_) -or $Rx.Modules.IsMatch($_) })
            if ($bad.Count -gt 0) { Add-Sys 'high' 'deleted' 'Cheat mod was loaded in the last game session but its jar is gone' ($bad -join ', ') $null 'logs/latest.log vs mods folder' }
            $liveGone = $false
            foreach ($ri in @($script:Instances)) { if ($ri.GameDir -and ([string]$ri.GameDir).TrimEnd('\') -ieq $GameDir.TrimEnd('\')) { $liveGone = $true } }
            if ($liveGone -and $bad.Count -gt 0) {
                $liveSev = 'high'
                Add-Sys $liveSev 'injected' 'The running game has mods loaded that are not in its mods folder (injected, or loaded from another folder)' ("{0}: {1}" -f $gone.Count, ((@($gone) | Select-Object -First 15) -join ', ')) $null 'logs/latest.log vs mods folder'
            } elseif ($liveGone) {
                Add-Sys 'low' 'injected' 'The running game lists mods that have no jar of their own in the mods folder (usually bundled libraries)' ("{0}: {1}" -f $gone.Count, ((@($gone) | Select-Object -First 15) -join ', ')) $null 'logs/latest.log vs mods folder'
            } else {
                Add-Sys 'low' 'deleted' 'Mods loaded in the last session but not in the mods folder now' ("{0}: {1}" -f $gone.Count, ((@($gone) | Select-Object -First 15) -join ', ')) $null 'logs/latest.log vs mods folder'
            }
        }
    }

    foreach ($pair in @(@('crash-reports', '*.txt'), @('.', 'hs_err_pid*.log'))) {
        $dir = Join-Path $GameDir $pair[0]
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter $pair[1] -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5)) {
            $t = Read-TextFileSafe $f.FullName 10MB
            if (-not $t) { continue }
            $m = $Rx.Clients.Match($t)
            if ($m.Success) { Add-Sys 'medium' 'game-log' 'Crash report mentions a cheat client' ("{0} ('{1}')" -f $f.Name, $m.Value) $f.LastWriteTimeUtc 'crash report' }
        }
    }
}

function Join-Keybinds($Mods) {
    foreach ($mod in $Mods) {
        foreach ($h in @($mod.Hacks)) {
            if (-not $h) { continue }
            $hn = ($h.Name.ToLower() -replace '[^a-z0-9]', '')
            if ($hn.Length -lt 3) { continue }
            foreach ($kb in $script:Keybinds) {
                $kn = ($kb.Name.ToLower() -replace '[^a-z0-9]', '')
                if ($kn -eq $hn -or $kn.Contains($hn)) {
                    $kb.Used = $true
                    $old = $h.Keybind
                    $h.Keybind = $kb.Key
                    $note = "{0} (key chosen by the player)" -f $kb.Source
                    if ($old -and $old -ne $kb.Key) { $note += "; code default was $old" }
                    $h.KeybindSource = $note
                    break
                }
            }
        }
    }

    foreach ($kb in $script:Keybinds) {
        if (-not $kb.Used -and ($Rx.Modules.IsMatch($kb.Name) -or $Rx.Clients.IsMatch($kb.Name))) {
            Add-Sys 'medium' 'keybind' 'Hack-module or client key binding with no matching jar (unverified or residual)' ("{0} -> {1}  [{2}]" -f $kb.Name, $kb.Key, $kb.Source) $null 'keybinds'
        }
    }
}

function Test-CommandLine([string]$Text, [string]$Source, $Time) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return }

    if ($Text -match '(?i)CactusHacksDetect[or]r|mcscan|Scan\.ps1|CactusHacksDetect[or]r-SELF-MARKER|New-Object Regex|Rule\s*=\s*''|Sev\s*=\s*''|\$CmdDefs|\$ToolDefs') { return }

    if ($Text -match '(?i)\b(Get-MpPreference|Get-MpComputerStatus|Update-MpSignature|MSFT_MpPreference)\b' -and -not ($Text -match '(?i)\b(Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring)\b')) { return }
    foreach ($r in $CmdRules) {
        if ($r.Rx.IsMatch($Text)) { Add-Sys $r.Sev 'command' $r.Rule $Text $Time $Source }
    }
}

function Invoke-ProcessChecks {
    $procs = @()
    try { $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop) } catch {}
    if ($procs.Count -eq 0) { Set-ModuleNote 'process list unavailable'; return }
    $titles = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { if ($p.MainWindowTitle) { $titles[[int]$p.Id] = $p.MainWindowTitle } }
    $seen = @{}
    foreach ($p in $procs) {
        $name = [string]$p.Name; $path = [string]$p.ExecutablePath; $cl = [string]$p.CommandLine
        $title = ''; if ($titles.ContainsKey([int]$p.ProcessId)) { $title = $titles[[int]$p.ProcessId] }
        $started = $null; try { if ($p.CreationDate) { $started = $p.CreationDate.ToUniversalTime() } } catch {}
        $hit = Get-ToolHit "$name $path $title"
        if ($hit) {
            $key = "$($hit.Cat)|$($name.ToLower())"
            if (-not $seen[$key]) {
                $seen[$key] = $true
                Add-Sys $hit.Sev 'process' $hit.Rule ("{0} (PID {1}) {2}" -f $name, $p.ProcessId, $path) $started 'running processes'
            }
        }
        if ($title -and $name -match '(?i)^javaw?\.exe$' -and $Rx.Clients.IsMatch($title)) {
            Add-Sys 'high' 'process' 'Game window title names a cheat client' $title $started 'window title'
        }
        if ($cl -and $name -match '(?i)^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)\.exe$') {
            Test-CommandLine $cl ("running {0} (PID {1})" -f $name, $p.ProcessId) $started
        }
    }

    foreach ($id in $titles.Keys) {
        $h = Get-ToolHit $titles[$id]
        if ($h -and $h.Cat -in 'injector', 'memedit', 'clicker', 'adapter', 'macro') { Add-Sys $h.Sev 'process' ($h.Rule + ' (window title)') $titles[$id] $null 'window title' }
    }
}

function Find-StrayModJars($KnownPaths) {
    $found = New-Object System.Collections.Generic.List[object]
    $roots = New-Object System.Collections.Generic.List[string]
    if ($env:USERPROFILE) { foreach ($b in 'Downloads', 'Desktop', 'Documents') { $roots.Add((Join-Path $env:USERPROFILE $b)) } }
    if ($env:TEMP) { $roots.Add($env:TEMP) }
    if ($env:APPDATA) { $roots.Add((Join-Path $env:APPDATA '.minecraft')) }
    foreach ($ri in @($script:Instances)) { if ($ri.GameDir) { $roots.Add([string]$ri.GameDir) } }
    $cut = $script:NowUtc.AddDays(-120)
    $metaNames = 'fabric.mod.json', 'quilt.mod.json', 'META-INF/mods.toml', 'META-INF/neoforge.mods.toml', 'mcmod.info'
    foreach ($r in @($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        $depth = 2
        if ($r -match '(?i)\.minecraft|instances|\\mods$') { $depth = 1 }
        $cands = @(Get-ChildItem -LiteralPath $r -File -Force -Recurse -Depth $depth -Filter '*.jar' -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 2KB -and $_.Length -lt 80MB -and $_.LastWriteTimeUtc -gt $cut -and -not $KnownPaths.ContainsKey($_.FullName) } | Select-Object -First 150)
        foreach ($fi in $cands) {
            $isMod = $false
            try {
                $z = [IO.Compression.ZipFile]::OpenRead($fi.FullName)
                try { foreach ($en in $z.Entries) { if ($metaNames -contains $en.FullName) { $isMod = $true; break } } } finally { $z.Dispose() }
            } catch {}
            if ($isMod) { $found.Add($fi) }
            if ($found.Count -ge 60) { break }
        }
    }
    return $found.ToArray()
}

function Get-JvmModuleFindings([int]$ProcId) {
    $out = @()
    $mods = @()
    try { $mods = @((Get-Process -Id $ProcId -ErrorAction Stop).Modules) } catch { return @(New-Finding 'low' 'jvm' 'Could not list loaded DLLs (try Administrator)' '' "PID $ProcId") }
    $safeRx = '(?i)^(' + [regex]::Escape($env:SystemRoot) + '|' + [regex]::Escape($env:ProgramFiles) + '|' + [regex]::Escape(${env:ProgramFiles(x86)}) + ')'
    $runtimeRx = '(?i)[\\/](runtime|jre|jdk|java|javaw?[-_0-9.a-z]*|\.minecraft[\\/]runtime|Packages[\\/]Microsoft\.4297127D64EC6[^\\/]*)[\\/]'
    $nativeOkRx = '(?i)(lwjgl|glfw|jemalloc|openal|jna|opus|sqlite|zstd|imgui|ffmpeg|steam_api|nanovg|stb|tinyfd|discord|mcef|jcef|libcef|chrome|jansi|lzma|snappy|rnnoise|speex|voicechat|vulkan|natives|ogl|nvoglv|atio|igd|ig9|amdvlk|d3d|dxil)'
    $userRx = '(?i)[\\/](AppData|Temp|Downloads|Desktop|Documents|ProgramData|Users[\\/]Public)[\\/]'
    $sigChecks = 0
    foreach ($m in $mods) {
        $path = [string]$m.FileName; $leaf = [string]$m.ModuleName
        if (-not $path) { continue }
        if ($Rx.Clients.IsMatch($leaf) -or $Rx.Markers.IsMatch($leaf)) { $out += New-Finding 'high' 'jvm' 'DLL named after a cheat client is loaded in the game' (Hide-User $path) "PID $ProcId"; continue }
        $inj = Get-ToolHit $leaf
        if ($inj -and $inj.Cat -in 'injector', 'memedit', 'clicker') { $out += New-Finding 'high' 'jvm' 'Cheat-tool DLL is loaded in the game' (Hide-User $path) "PID $ProcId"; continue }
        if ($path -match $safeRx -or $path -match $runtimeRx) { continue }
        if ($path -match $userRx -and $leaf -notmatch $nativeOkRx -and $sigChecks -lt 30) {
            $sigChecks++
            $st = 'Unknown'; try { $st = [string](Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop).Status } catch {}
            if ($st -ne 'Valid') { $out += New-Finding 'medium' 'jvm' 'Unsigned DLL from a user folder is loaded in the game' (Hide-User $path) "PID $ProcId" }
        }
    }
    return $out
}

function Invoke-MemoryScan([int]$ProcId) {
    if ($NoMemory) { return $null }
    if (-not $script:Native) { return [pscustomobject]@{ Ok = $false; Note = 'native helper unavailable'; ClientHits = @(); ModuleHits = @(); ScannedMB = 0 } }
    if (-not [Environment]::Is64BitProcess) { return [pscustomobject]@{ Ok = $false; Note = 'needs 64-bit PowerShell'; ClientHits = @(); ModuleHits = @(); ScannedMB = 0 } }
    $terms = [string[]]@($MemClientTerms + $MemModuleTerms)
    $r = [CactusHacksDetector.MemScan]::Scan($ProcId, $terms, $MemoryScanSeconds, [long]3GB)
    $ch = @(); $mh = @()
    if ($r.Hits) {
        foreach ($k in $r.Hits.Keys) {
            $row = [pscustomobject]@{ Term = $k; Count = $r.Hits[$k] }
            if ($MemClientTerms -contains $k) { $ch += $row } else { $mh += $row }
        }
    }
    $note = $r.Error; if ($r.TimedOut) { $note = 'time/size limit reached (partial scan)' }
    [pscustomobject]@{ Ok = $r.Ok; Note = $note; ClientHits = $ch; ModuleHits = $mh; ScannedMB = [math]::Round($r.BytesScanned / 1MB) }
}

function Get-JvmReport {
    $out = @()
    foreach ($p in (Get-McJavaProcesses)) {
        $cl = [string]$p.CommandLine; $flags = @()
        foreach ($m in [regex]::Matches($cl, '(?i)-javaagent:("[^"]+"|\S+)')) { $flags += New-Finding 'medium' 'jvm' 'Java agent loaded' (Hide-User $m.Groups[1].Value) "PID $($p.ProcessId)" }
        foreach ($m in [regex]::Matches($cl, '(?i)-Xbootclasspath/[pa]:("[^"]+"|\S+)')) { $flags += New-Finding 'high' 'jvm' 'Bootclasspath injection' (Hide-User $m.Groups[1].Value) "PID $($p.ProcessId)" }
        foreach ($m in [regex]::Matches($cl, '(?i)-agentlib:jdwp\S*')) { $flags += New-Finding 'high' 'jvm' 'Debug agent attached (jdwp)' $m.Value "PID $($p.ProcessId)" }
        foreach ($m in [regex]::Matches($cl, '(?i)-agentpath:("[^"]+"|\S+)')) { $flags += New-Finding 'high' 'jvm' 'Native agent loaded' (Hide-User $m.Groups[1].Value) "PID $($p.ProcessId)" }
        foreach ($m in [regex]::Matches($cl, '(?i)-Djava\.system\.class\.loader=(\S+)')) { $flags += New-Finding 'medium' 'jvm' 'Custom system class loader' $m.Groups[1].Value "PID $($p.ProcessId)" }
        foreach ($m in [regex]::Matches($cl, '(?i)-Dfabric\.addMods=("[^"]+"|\S+)')) { $flags += New-Finding 'high' 'jvm' 'Mods are loaded from outside the mods folder (fabric.addMods)' (Hide-User $m.Groups[1].Value) "PID $($p.ProcessId)" }
        $cpm = [regex]::Match($cl, '(?i)(?:^|\s)-(?:cp|classpath|-class-path)\s+("[^"]+"|\S+)')
        if ($cpm.Success) {
            foreach ($e in ($cpm.Groups[1].Value.Trim('"') -split ';')) {
                if ($e -notmatch '(?i)\.jar$') { continue }
                if ($e -match '(?i)[\\/](libraries|versions|runtime|natives|meta|bin|NewLaunch|launcher)[\\/]|authlib|lwjgl|LabyMod|\.lunarclient|\.feather|\.badlion|BadlionClient') { continue }
                $cpSev = 'low'
                if ($e -match '(?i)[\\/](Downloads|Desktop|Documents|Temp|ProgramData|Users[\\/]Public)[\\/]') { $cpSev = 'medium' }
                $flags += New-Finding $cpSev 'jvm' 'A jar outside the usual library folders is on the game classpath' (Hide-User $e) "PID $($p.ProcessId)"
            }
        }
        $started = $null; try { $started = $p.CreationDate.ToUniversalTime() } catch {}
        if ($started -and (-not $script:JvmStartUtc -or $started -lt $script:JvmStartUtc)) { $script:JvmStartUtc = $started }
        $startedText = $null; if ($started) { $startedText = $started.ToString('o') }
        $mem = $null
        if (-not $ModsOnly) {
            $flags += @(Get-JvmModuleFindings ([int]$p.ProcessId))
            Write-Line ("  scanning memory of PID {0} (read-only, up to {1}s)..." -f $p.ProcessId, $MemoryScanSeconds) DarkGray
            $mem = Invoke-MemoryScan ([int]$p.ProcessId)
            if ($mem) {
                foreach ($h in $mem.ClientHits) { $flags += New-Finding 'high' 'memory' 'Cheat-client string found in the game memory' ("{0} (x{1}) - confirm with other evidence; chat text can also contain names" -f $h.Term, $h.Count) "PID $($p.ProcessId)" }
                if (@($mem.ModuleHits).Count -ge 3) { $flags += New-Finding 'medium' 'memory' 'Several hack-module names found in the game memory' ((@($mem.ModuleHits) | ForEach-Object { "{0} x{1}" -f $_.Term, $_.Count }) -join ', ') "PID $($p.ProcessId)" }
                elseif (@($mem.ModuleHits).Count -gt 0) { $flags += New-Finding 'low' 'memory' 'Hack-module name(s) in the game memory' ((@($mem.ModuleHits) | ForEach-Object { "{0} x{1}" -f $_.Term, $_.Count }) -join ', ') "PID $($p.ProcessId)" }
            }
        }
        $out += [pscustomobject]@{ Pid = $p.ProcessId; Name = $p.Name; StartedUtc = $startedText; Findings = @($flags); Memory = $mem }
    }
    return $out
}

function Invoke-HistoryChecks {
    $hp = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path -LiteralPath $hp) {
        $fi = Get-Item -LiteralPath $hp
        if ($fi.Length -eq 0) {
            Add-Sys 'medium' 'history' 'PowerShell history file exists but is empty (wiped?)' $hp $fi.LastWriteTimeUtc 'ConsoleHost_history.txt'
        } else {
            $lines = @(Get-Content -LiteralPath $hp -Tail 3000 -ErrorAction SilentlyContinue)
            foreach ($ln in $lines) { Test-CommandLine $ln 'PowerShell history' $fi.LastWriteTimeUtc }
            if (Test-InWindow $fi.LastWriteTimeUtc) { Add-Sys 'low' 'history' 'PowerShell was used inside the lookback window' ("{0} history lines" -f $lines.Count) $fi.LastWriteTimeUtc 'ConsoleHost_history.txt' }
        }
    } else {
        Add-Sys 'low' 'history' 'No PowerShell history file (never used, or deleted)' $hp $null 'ConsoleHost_history.txt'
    }
    try {
        $o = Get-PSReadLineOption -ErrorAction Stop
        if ([string]$o.HistorySaveStyle -eq 'SaveNothing') { Add-Sys 'high' 'history' 'PowerShell history saving is switched off' 'HistorySaveStyle = SaveNothing' $null 'PSReadLine' }
    } catch {}

    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
    if (Test-Path $k) {
        $props = Get-ItemProperty $k
        foreach ($pn in $props.PSObject.Properties) {
            if ($pn.Name -match '^[a-z]$') { Test-CommandLine (([string]$pn.Value) -replace '\\1$', '') 'Win+R history (RunMRU)' $null }
        }
    }
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
    if (Test-Path $k) {
        $props = Get-ItemProperty $k
        foreach ($pn in $props.PSObject.Properties) {
            if ($pn.Name -like 'url*' -and ([string]$pn.Value) -match '(?i)prefetch|recycle|[\\/]recent\b|winevt|\.minecraft|[\\/]mods\b') {
                Add-Sys 'low' 'history' 'Explorer address bar was used on a sensitive path' ([string]$pn.Value) $null 'TypedPaths'
            }
        }
    }
}

function Invoke-EventLogChecks {
    $since = $script:NowUtc.AddDays(-30).ToLocalTime()
    foreach ($e in (Get-EventsSafe @{ LogName = 'System'; Id = 104; StartTime = $since })) {
        $sev = 'medium'; if (Test-InWindow $e.TimeCreated) { $sev = 'high' }
        Add-Sys $sev 'log-tamper' 'An event log was cleared' (Limit-Text ([string]$e.Message) 140) $e.TimeCreated 'System log (event 104)'
    }
    foreach ($e in (Get-EventsSafe @{ LogName = 'Security'; Id = 1102; StartTime = $since })) {
        $sev = 'medium'; if (Test-InWindow $e.TimeCreated) { $sev = 'high' }
        Add-Sys $sev 'log-tamper' 'The Security log was cleared' (Limit-Text ([string]$e.Message) 140) $e.TimeCreated 'Security log (event 1102)'
    }
    foreach ($e in (Get-EventsSafe @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 1; StartTime = $script:NowUtc.AddDays(-7).ToLocalTime() } 40)) {
        $msg = [string]$e.Message

        $isRoutine = ($msg -match '(?i)routine time synchronization|time service|w32time|reason:\s*0\b|synchronized with|application or system component')
        $deltaSeconds = $null
        try {
            if ($msg -match '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*Z).*?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*Z)') {
                $t1 = [datetime]::Parse($Matches[1]); $t2 = [datetime]::Parse($Matches[2])
                $deltaSeconds = [math]::Abs(($t2 - $t1).TotalSeconds)
            }
        } catch {}
        if ($isRoutine -or ($deltaSeconds -ne $null -and $deltaSeconds -lt 3600)) { continue }
        $sev = 'low'; if (Test-InWindow $e.TimeCreated) { $sev = 'medium' }
        Add-Sys $sev 'log-tamper' 'Large system clock shift' (Limit-Text $msg 160) $e.TimeCreated 'System log (Kernel-General 1)'
    }
    $dl = 'Microsoft-Windows-Windows Defender/Operational'
    foreach ($e in (Get-EventsSafe @{ LogName = $dl; Id = 1116, 1117; StartTime = $script:NowUtc.AddDays(-7).ToLocalTime() } 40)) {
        $nm = ''; if (([string]$e.Message) -match 'Name:\s*(\S+)') { $nm = $Matches[1] }
        Add-Sys 'medium' 'defender' 'Windows Defender detected a threat' $nm $e.TimeCreated 'Defender log'
    }
    foreach ($e in (Get-EventsSafe @{ LogName = $dl; Id = 5001; StartTime = $script:NowUtc.AddDays(-7).ToLocalTime() } 20)) {
        $sev = 'medium'; if (Test-InWindow $e.TimeCreated) { $sev = 'high' }
        Add-Sys $sev 'defender' 'Defender real-time protection was switched off' '' $e.TimeCreated 'Defender log (5001)'
    }
    foreach ($e in (Get-EventsSafe @{ LogName = $dl; Id = 5007; StartTime = $script:NowUtc.AddDays(-7).ToLocalTime() } 60)) {
        $m = [string]$e.Message
        if ($m -match '(?i)Exclusions') {
            $line = ($m -split "`r?`n" | Where-Object { $_ -match '(?i)Exclusions' } | Select-Object -First 1)
            $sev = 'medium'; if (Test-InWindow $e.TimeCreated) { $sev = 'high' }
            Add-Sys $sev 'defender' 'Defender exclusions were changed' (Limit-Text $line 200) $e.TimeCreated 'Defender log (5007)'
        }
    }
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        foreach ($pth in @($mp.ExclusionPath)) {
            if (-not $pth -or $pth -match '^N/A') { continue }
            $sev = 'low'; if ($pth -match '(?i)minecraft|downloads|desktop|[\\/]temp|appdata') { $sev = 'high' }
            Add-Sys $sev 'defender' 'Defender exclusion path' $pth $null 'Get-MpPreference'
        }
        foreach ($pr in @($mp.ExclusionProcess)) { if ($pr -and $pr -notmatch '^N/A') { Add-Sys 'medium' 'defender' 'Defender exclusion for a process' $pr $null 'Get-MpPreference' } }
    } catch {}

    $sbEvents = @(Get-EventsSafe @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $script:WindowStart.ToLocalTime() } 300)
    $ownBlocks = @{}
    foreach ($e in $sbEvents) {
        $mt = [string]$e.Message
        if ($e.ProcessId -eq $PID -or $mt -match '(?i)CactusHacksDetect[or]r|mcscan-api|ProfileBuilder|Invoke-Module|Write-Section') {
            if ($mt -match 'ScriptBlock ID:\s*([0-9a-fA-F-]{36})') { $ownBlocks[$Matches[1].ToLower()] = $true }
        }
    }
    foreach ($e in $sbEvents) {
        $mt = [string]$e.Message
        if ($e.ProcessId -eq $PID) { continue }
        if ($mt -match 'ScriptBlock ID:\s*([0-9a-fA-F-]{36})' -and $ownBlocks.ContainsKey($Matches[1].ToLower())) { continue }
        Test-CommandLine (Limit-Text $mt 3000) 'PowerShell script-block log' $e.TimeCreated
    }
    foreach ($e in (Get-EventsSafe @{ LogName = 'Security'; Id = 4688; StartTime = $script:WindowStart.ToLocalTime() } 1500)) {
        $m = [string]$e.Message; $np = ''; $cl = ''
        if ($m -match 'New Process Name:\s*(.+)') { $np = $Matches[1].Trim() }
        if ($m -match 'Process Command Line:\s*(.+)') { $cl = $Matches[1].Trim() }
        $h = Get-ToolHit "$np"
        if ($h -and $h.Cat -in 'injector', 'memedit', 'clicker', 'adapter', 'wiper', 'macro') { Add-Sys $h.Sev 'process' ($h.Rule + ' was started') $np $e.TimeCreated 'Security log (4688)' }
        if ($cl) { Test-CommandLine $cl 'process-creation log (4688)' $e.TimeCreated }
    }
    if (-not $script:IsAdmin) { Set-ModuleNote 'partial: Security log needs Administrator' }
}

$script:Exec = New-Object System.Collections.Generic.List[object]
function Add-ExecRow([string]$Src, [string]$Path, $Time, $Runs) {
    [void]$script:Exec.Add([pscustomobject]@{ Source = $Src; Path = $Path; Time = $Time; Runs = $Runs })
}

function ConvertFrom-Rot13([string]$s) {
    $sb = New-Object Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 65 -and $c -le 90) { [void]$sb.Append([char](65 + (($c - 65 + 13) % 26))) }
        elseif ($c -ge 97 -and $c -le 122) { [void]$sb.Append([char](97 + (($c - 97 + 13) % 26))) }
        else { [void]$sb.Append($ch) }
    }
    $sb.ToString()
}

function Read-PrefetchTraces {
    $reg = $null
    try { $reg = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction Stop).EnablePrefetcher } catch {}
    if ($null -ne $reg -and [int]$reg -eq 0) { Add-Sys 'medium' 'evasion' 'Prefetch is disabled in the registry' 'EnablePrefetcher = 0' $null 'registry' }
    try { if ((Get-Service -Name SysMain -ErrorAction Stop).StartType -eq 'Disabled') { Add-Sys 'medium' 'evasion' 'The SysMain (Superfetch/Prefetch) service is disabled' 'SysMain' $null 'services' } } catch {}
    $pf = Join-Path $env:SystemRoot 'Prefetch'
    $files = @()
    try { $files = @(Get-ChildItem -LiteralPath $pf -Filter '*.pf' -File -ErrorAction Stop) } catch { Set-ModuleNote 'Prefetch needs Administrator'; return }
    if ($files.Count -eq 0 -and ($null -eq $reg -or [int]$reg -ne 0)) { Add-Sys 'high' 'evasion' 'The Prefetch folder is empty (cleared?)' $pf $null 'Prefetch' }
    foreach ($f in $files) { Add-ExecRow 'Prefetch' ($f.Name -replace '-[0-9A-Fa-f]{8}\.pf$', '') $f.LastWriteTimeUtc 0 }
}

function Read-BamTraces {
    foreach ($root in 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings') {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($sid in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $sid.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($pn in $props.PSObject.Properties) {
                if ($pn.Value -is [byte[]] -and $pn.Value.Length -ge 8) {
                    try { $ft = [BitConverter]::ToInt64($pn.Value, 0); if ($ft -gt 0) { Add-ExecRow 'BAM' $pn.Name ([DateTime]::FromFileTimeUtc($ft)) 0 } } catch {}
                }
            }
        }
    }
}

function Read-UserAssistTraces {
    $ua = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    if (-not (Test-Path $ua)) { return }
    foreach ($g in @(Get-ChildItem $ua -ErrorAction SilentlyContinue)) {
        $key = Get-Item -LiteralPath ($g.PSPath + '\Count') -ErrorAction SilentlyContinue
        if (-not $key) { continue }
        foreach ($vn in $key.GetValueNames()) {
            $data = $key.GetValue($vn)
            if ($data -is [byte[]] -and $data.Length -ge 68) {
                try {
                    $runs = [BitConverter]::ToUInt32($data, 4)
                    $ft = [BitConverter]::ToInt64($data, 60)
                    $t = $null; if ($ft -gt 0) { $t = [DateTime]::FromFileTimeUtc($ft) }
                    Add-ExecRow 'UserAssist' (ConvertFrom-Rot13 $vn) $t $runs
                } catch {}
            }
        }
    }
}

function Read-ShimCacheTraces {
    $d = $null
    try { $d = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache } catch { return }
    if (-not ($d -is [byte[]]) -or $d.Length -lt 64) { return }
    $off = [int][BitConverter]::ToUInt32($d, 0)
    if ($off -lt 0x30 -or $off -gt 0x100 -or ([Text.Encoding]::ASCII.GetString($d, $off, 4) -ne '10ts')) { Set-ModuleNote 'ShimCache format not recognised (Windows 10/11 only)'; return }
    $pos = $off; $n = 0
    while ($pos + 16 -lt $d.Length -and $n -lt 1100) {
        if ([Text.Encoding]::ASCII.GetString($d, $pos, 4) -ne '10ts') { break }
        $entryLen = [int][BitConverter]::ToUInt32($d, $pos + 8)
        $pathLen = [int][BitConverter]::ToUInt16($d, $pos + 12)
        if ($pathLen -le 0 -or ($pos + 14 + $pathLen + 8) -gt $d.Length) { break }
        $path = [Text.Encoding]::Unicode.GetString($d, $pos + 14, $pathLen)
        $t = $null
        try { $ft = [BitConverter]::ToInt64($d, $pos + 14 + $pathLen); if ($ft -gt 0) { $t = [DateTime]::FromFileTimeUtc($ft) } } catch {}
        Add-ExecRow 'ShimCache' $path $t 0
        $pos = $pos + 12 + $entryLen
        $n++
    }
}

function Test-ExecRows {
    $userRx = '(?i)[\\/](Users|Documents and Settings)[\\/][^\\/]+[\\/](Downloads|Desktop|Documents|AppData[\\/]Local[\\/]Temp|AppData[\\/]Roaming)[\\/]'
    $afRx = '(?i)^(wevtutil|fsutil|cipher|vssadmin)\.exe$'
    $groups = $script:Exec | Group-Object { (([string]$_.Path) -replace '^.*[\\/]', '').ToLower() }
    $userRuns = 0
    foreach ($g in $groups) {
        $first = $g.Group[0]
        $leaf = $g.Name
        $times = @($g.Group | Where-Object { $_.Time } | ForEach-Object { $_.Time })
        $latest = $null; if ($times.Count -gt 0) { $latest = ($times | Sort-Object -Descending | Select-Object -First 1) }
        $sources = ((@($g.Group | ForEach-Object { $_.Source }) | Select-Object -Unique) -join '+')
        $inWin = ($latest -and (Test-InWindow $latest))
        $hay = "$leaf $($first.Path)"
        $hit = Get-ToolHit $hay
        $clientHit = $Rx.Clients.IsMatch($hay) -or $Rx.Markers.IsMatch($hay)
        if ($clientHit) { Add-Sys 'high' 'execution' 'A cheat-client program was run' ("{0} [{1}]" -f $first.Path, $sources) $latest 'execution traces'; continue }
        if ($hit -and $hit.Cat -notin 'peripheral', 'sniffer') {
            $sev = $hit.Sev
            if ($hit.Cat -eq 'remote' -and -not $inWin) { $sev = 'low' }
            if ($hit.Cat -eq 'vm' -and -not $inWin) { $sev = 'low' }
            Add-Sys $sev 'execution' ($hit.Rule + ' was run') ("{0} [{1}]" -f $first.Path, $sources) $latest 'execution traces'
            continue
        }
        if ($leaf -match $afRx -and $inWin) { Add-Sys 'low' 'execution' 'A log/file-system admin tool was run inside the window' ("{0} [{1}]" -f $leaf, $sources) $latest 'execution traces'; continue }
        if ($inWin -and $first.Path -match $userRx -and $leaf -match '\.exe$' -and $userRuns -lt 15) {
            $userRuns++
            Add-Sys 'low' 'execution' 'Program run from a user folder inside the window' ("{0} [{1}]" -f $first.Path, $sources) $latest 'execution traces'
        }
    }
}

function Invoke-RecycleBinChecks {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $total = 0; $inWin = 0
    $traceDel = New-Object System.Collections.Generic.List[string]
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -ne 'Fixed' -and $d.DriveType -ne 'Removable') { continue }
        $dir = Join-Path $d.RootDirectory.FullName ('$Recycle.Bin\' + $sid)
        $items = @()
        try { $items = @(Get-ChildItem -LiteralPath $dir -Force -Filter '$I*' -File -ErrorAction Stop) } catch { continue }
        foreach ($f in $items) {
            $total++
            try {
                $b = [IO.File]::ReadAllBytes($f.FullName)
                if ($b.Length -lt 28) { continue }
                $ver = [BitConverter]::ToInt64($b, 0)
                $ft = [BitConverter]::ToInt64($b, 16)
                $when = [DateTime]::FromFileTimeUtc($ft)
                if ($ver -eq 2) { $len = [BitConverter]::ToInt32($b, 24); $take = [math]::Min($len * 2, $b.Length - 28); $path = [Text.Encoding]::Unicode.GetString($b, 28, [math]::Max(0, $take)).TrimEnd([char]0) }
                else { $take = [math]::Min(520, $b.Length - 24); $path = [Text.Encoding]::Unicode.GetString($b, 24, [math]::Max(0, $take)).TrimEnd([char]0) }
                $leaf = $path -replace '^.*[\\/]', ''
                $ext = Get-Ext $leaf
                $win = Test-InWindow $when
                if ($win) { $inWin++ }
                $hit = Get-ToolHit $leaf
                if ($Rx.Clients.IsMatch($leaf) -or $Rx.Modules.IsMatch($leaf) -or $Rx.Markers.IsMatch($leaf) -or ($hit -and $hit.Cat -in 'injector', 'memedit', 'clicker', 'adapter', 'wiper')) {
                    Add-Sys 'high' 'deleted' 'A cheat-named file was moved to the Recycle Bin' $path $when 'Recycle Bin'
                } elseif ($ext -in '.pf', '.evtx' -or $leaf -match '(?i)ConsoleHost_history') {
                    [void]$traceDel.Add($path)
                } elseif ($win -and ($ext -eq '.jar' -or $path -match '(?i)[\\/](\.minecraft|mods)[\\/]')) {
                    Add-Sys 'medium' 'deleted' 'Minecraft mod or game jar was deleted inside lookback window' $path $when 'Recycle Bin'
                }
            } catch {}
        }
    }
    if ($traceDel.Count -gt 0) { Add-Sys 'medium' 'deleted' 'Prefetch / event-log / history files are in the Recycle Bin (Windows and cleaners do this too)' ("{0} file(s), e.g. {1}" -f $traceDel.Count, ((@($traceDel) | Select-Object -First 3) -join '; ')) $null 'Recycle Bin' }
    if ($inWin -gt 0) { Add-Sys 'low' 'deleted' 'Items were deleted inside the lookback window' ("{0} item(s) in the Recycle Bin were deleted recently ({1} total)" -f $inWin, $total) $null 'Recycle Bin' }
}

function Convert-UsnReason([string]$r) {
    if ($r -match '^\s*0x([0-9a-fA-F]+)') {
        $v = [Convert]::ToInt64($Matches[1], 16)
        $names = @()
        if ($v -band 0x100) { $names += 'create' }; if ($v -band 0x200) { $names += 'DELETE' }
        if ($v -band 0x1000) { $names += 'rename-from' }; if ($v -band 0x2000) { $names += 'rename-to' }
        if ($v -band 0x4) { $names += 'truncate' }; if ($v -band 0x1) { $names += 'overwrite' }
        if ($names.Count -gt 0) { return ($names -join '+') }
    }
    return (Limit-Text $r 60)
}

function Invoke-UsnChecks {
    if ($NoUsn) { Set-ModuleSkipped 'skipped (-NoUsn)'; return }
    if (-not $script:IsAdmin) { Set-ModuleSkipped 'needs Administrator'; return }
    $drive = $env:SystemDrive; if (-not $drive) { $drive = 'C:' }
    $q = @(& fsutil.exe usn queryjournal $drive 2>$null)
    $next = $null; $low = 0
    foreach ($l in $q) {
        if ($l -match '(?i)(Next Usn|N.chste USN)\s*:\s*0x([0-9a-f]+)') { $next = [Convert]::ToInt64($Matches[2], 16) }
        if ($l -match '(?i)(Lowest Valid Usn)\s*:\s*0x([0-9a-f]+)') { $low = [Convert]::ToInt64($Matches[2], 16) }
    }
    if ($null -eq $next) { Set-ModuleSkipped 'USN journal not available'; return }
    $start = [math]::Max($low, $next - 64MB)
    $nameRx = New-Object Regex(('(?i)(' + $Sig.Clients + '|' + $Sig.Modules + '|\.pf$|\.evtx$|ConsoleHost_history|AutomaticDestinations|\.ahk$|\.jar$|\.exe$|\.dll$)').Replace('(?i)(?i)', '(?i)'), 'Compiled')
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = 'fsutil.exe'
    $psi.Arguments = "usn readjournal $drive startusn=$start csv"
    $psi.RedirectStandardOutput = $true; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $proc = [Diagnostics.Process]::Start($psi)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $header = $null; $iName = -1; $iReason = -1; $iTime = -1
    $found = 0; $lines = 0; $timedOut = $false
    while ($null -ne ($line = $proc.StandardOutput.ReadLine())) {
        $lines++
        if ($null -eq $header) {
            if ($line -match '(?i)file name' -and $line -match '(?i)reason') {
                $header = $line.Split(',')
                for ($i = 0; $i -lt $header.Count; $i++) {
                    $h = $header[$i].Trim().Trim('"').ToLower()
                    if ($h -eq 'file name') { $iName = $i } elseif ($h -eq 'reason') { $iReason = $i } elseif ($h -like 'time stamp*') { $iTime = $i }
                }
            }
            continue
        }
        if (($lines % 20000) -eq 0 -and $sw.Elapsed.TotalSeconds -gt 90) { $timedOut = $true; try { $proc.Kill() } catch {}; break }
        if (-not $nameRx.IsMatch($line)) { continue }
        $f = $line.Split(',')
        $name = $line; $reason = ''; $ts = $null
        if ($iName -ge 0 -and $iName -lt $f.Count) { $name = $f[$iName].Trim().Trim('"') }
        if ($iReason -ge 0 -and $iReason -lt $f.Count) { $reason = Convert-UsnReason $f[$iReason] }
        if ($iTime -ge 0 -and $iTime -lt $f.Count) { try { $ts = ([datetime]::Parse($f[$iTime].Trim().Trim('"'))).ToUniversalTime() } catch {} }
        $isDel = ($reason -match '(?i)delete|rename-from|truncate|overwrite')
        $strong = ($Rx.Clients.IsMatch($name) -or $Rx.Modules.IsMatch($name))
        if ($strong) { Add-Sys 'high' 'deleted' 'Cheat-named file seen in the NTFS change journal' ("{0} [{1}]" -f $name, $reason) $ts 'USN journal'; $found++ }
        elseif ($isDel -and $name -match '(?i)\.(pf|evtx)$|ConsoleHost_history|AutomaticDestinations') { Add-Sys 'high' 'deleted' 'Forensic trace file deleted/changed (per NTFS journal)' ("{0} [{1}]" -f $name, $reason) $ts 'USN journal'; $found++ }
        elseif ($isDel -and $name -match '(?i)\.(jar|ahk)$' -and (-not $ts -or (Test-InWindow $ts)) -and $found -lt 40) { Add-Sys 'low' 'deleted' 'Jar/script deleted or renamed recently (per NTFS journal)' ("{0} [{1}]" -f $name, $reason) $ts 'USN journal'; $found++ }
    }
    if (-not $proc.HasExited) { try { $proc.Kill() } catch {} }
    if ($timedOut) { Set-ModuleNote 'journal read stopped after 90s (partial)' }
    elseif ($lines -le 1) { Set-ModuleNote 'journal returned no data' }
}

function Invoke-RecentFileChecks {
    $dirs = New-Object System.Collections.Generic.List[string]
    foreach ($d in [Environment]::GetFolderPath('Desktop'), (Join-Path $env:USERPROFILE 'Downloads'), [Environment]::GetFolderPath('MyDocuments'), $env:TEMP, (Join-Path $env:APPDATA '.minecraft')) {
        if ($d -and (Test-Path -LiteralPath $d)) { $dirs.Add($d) }
    }
    $exts = '.jar', '.exe', '.dll', '.zip', '.rar', '.7z', '.ahk', '.bat', '.cmd', '.ps1', '.vbs', '.msi'
    $shown = 0
    foreach ($d in $dirs) {
        $files = @(Get-ChildItem -LiteralPath $d -File -Recurse -Depth 2 -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in $exts -and ($_.LastWriteTimeUtc -ge $script:WindowStart -or $_.CreationTimeUtc -ge $script:WindowStart) } | Select-Object -First 150)
        foreach ($f in $files) {
            $hit = Get-ToolHit $f.Name
            if ($Rx.Clients.IsMatch($f.Name) -or $Rx.Modules.IsMatch($f.Name) -or ($hit -and $hit.Cat -notin 'peripheral', 'sniffer')) {
                Add-Sys 'high' 'file-activity' 'Cheat-named file created/changed inside the window' $f.FullName $f.LastWriteTimeUtc 'recent files'
            } elseif ($shown -lt 25 -and $f.Name -notlike 'CactusHacksDetector-*') {
                $shown++
                Add-Sys 'low' 'file-activity' 'Program/archive created or changed inside the window' $f.FullName $f.LastWriteTimeUtc 'recent files'
            }
        }
    }
    $recent = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
    foreach ($l in @(Get-ChildItem -LiteralPath $recent -Filter '*.lnk' -File -ErrorAction SilentlyContinue)) {
        $n = $l.BaseName
        $hit = Get-ToolHit $n
        if ($Rx.Clients.IsMatch($n) -or $Rx.Modules.IsMatch($n) -or ($hit -and $hit.Cat -notin 'peripheral', 'sniffer')) {
            Add-Sys 'medium' 'file-activity' 'Recent-items shortcut points to a cheat-named file' $n $l.LastWriteTimeUtc 'Recent items'
        }
    }
}

function Invoke-DeviceChecks {
    $devs = @()
    try { $devs = @(Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -match '^(USB|USBSTOR|HID|BTHENUM|BTH)\\' }) } catch { Set-ModuleSkipped 'Get-PnpDevice unavailable'; return }
    $boot = $null; try { $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime() } catch {}
    $reported = 0; $checked = 0
    foreach ($d in $devs) {
        if ($checked -ge 250) { break }
        $checked++
        $arr = $null; $rem = $null
        try {
            $props = Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_LastRemovalDate' -ErrorAction Stop
            foreach ($p in $props) {
                if ($p.KeyName -like '*LastArrivalDate') { $arr = $p.Data } elseif ($p.KeyName -like '*LastRemovalDate') { $rem = $p.Data }
            }
        } catch {}
        $inA = ($arr -is [datetime]) -and (Test-InWindow $arr)
        $inR = ($rem -is [datetime]) -and (Test-InWindow $rem)

        if ($inA -and $boot -and ($arr.ToUniversalTime() -lt $boot.AddMinutes(3))) { $inA = $false }
        if (-not ($inA -or $inR)) { continue }
        $name = [string]$d.FriendlyName; if (-not $name) { $name = [string]$d.InstanceId }
        $cls = [string]$d.Class
        $adapter = Get-ToolHit $name
        $sev = 'low'
        if ($cls -in 'Keyboard', 'Mouse', 'HIDClass' -or $name -match '(?i)keyboard|mouse|gamepad|controller|macro') { $sev = 'medium' }
        elseif ($cls -in 'DiskDrive', 'WPD', 'USBSTOR' -or $name -match '(?i)mass storage|flash|disk') { $sev = 'medium' }
        if ($adapter -and $adapter.Cat -eq 'adapter') { $sev = 'high' }
        if ($reported -ge 30) { break }
        if ($inA) { $reported++; Add-Sys $sev 'usb' 'Device connected inside the lookback window' ("{0} [{1}] {2}" -f $name, $cls, $d.Status) $arr 'PnP' }
        if ($inR) { $reported++; Add-Sys $sev 'usb' 'Device disconnected inside the lookback window' ("{0} [{1}] {2}" -f $name, $cls, $d.Status) $rem 'PnP' }
    }
}

function Test-PrivateIp([string]$ip) {
    if (-not $ip) { return $false }
    return ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)') -or ($ip -match '^(fe80:|f[cd][0-9a-f]{2}:)')
}
function Test-LoopbackIp([string]$ip) { return ($ip -eq '::1' -or $ip -match '^127\.' -or $ip -eq '0.0.0.0' -or $ip -eq '::') }

function Invoke-NetworkChecks {
    $names = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $names[[int]$p.Id] = $p.ProcessName }
    $remoteRx = ($ToolSigs | Where-Object { $_.Cat -eq 'remote' } | Select-Object -First 1).Rx
    $conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
    foreach ($c in $conns) {
        $pn = ''; if ($names.ContainsKey([int]$c.OwningProcess)) { $pn = $names[[int]$c.OwningProcess] }
        $ra = [string]$c.RemoteAddress; $rp = [int]$c.RemotePort; $lp = [int]$c.LocalPort
        if (Test-LoopbackIp $ra) { continue }
        $link = ("{0} <-> {1}:{2}" -f $pn, $ra, $rp)
        if ($lp -eq 3389) { Add-Sys 'high' 'remote' 'A Remote Desktop session is connected to this PC' ("from {0} ({1})" -f $ra, $pn) $null 'TCP connections' }
        elseif ($rp -eq 3389) { Add-Sys 'medium' 'remote' 'This PC has an outgoing Remote Desktop connection' $link $null 'TCP connections' }
        if ($remoteRx -and $remoteRx.IsMatch($pn)) { Add-Sys 'low' 'remote' 'Remote desktop/assistance tool has an active connection (common for remote support)' $link $null 'TCP connections' }
        elseif (($rp -in 5900, 5901, 5902, 5938, 7070, 5985, 5986) -or ($lp -in 5900, 5901, 5902, 5938, 7070)) { Add-Sys 'medium' 'remote' 'Connection on a remote-control port' $link $null 'TCP connections' }
        if ($pn -match '(?i)^javaw?$' -and (Test-PrivateIp $ra)) {
            $sev = 'medium'; if ($rp -eq 25565) { $sev = 'low' }
            Add-Sys $sev 'network' 'The game is connected to a device on the local network' $link $null 'TCP connections'
        }
    }
    foreach ($l in @(Get-NetTCPConnection -State Listen -LocalPort 3389, 5900, 5938, 7070, 5985, 5986 -ErrorAction SilentlyContinue)) {
        Add-Sys 'low' 'remote' 'This PC is listening on a remote-control port' ("port {0} ({1})" -f $l.LocalPort, $names[[int]$l.OwningProcess]) $null 'TCP listeners'
    }
    foreach ($line in @(& quser 2>$null)) {
        if (([string]$line) -match 'rdp-tcp#\d+') {
            $sev = 'high'; if ($line -match '(?i)\bDisc') { $sev = 'medium' }
            Add-Sys $sev 'remote' 'A Remote Desktop session exists on this PC' (Limit-Text (([string]$line) -replace '\s+', ' ') 120) $null 'quser'
        }
    }
    foreach ($e in (Get-EventsSafe @{ LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id = 21, 22, 24, 25; StartTime = $script:NowUtc.AddHours(-24).ToLocalTime() } 60)) {
        $m = [string]$e.Message; $addr = ''
        if ($m -match 'Source Network Address:\s*(\S+)') { $addr = $Matches[1] }
        if ($addr -and $addr -ne 'LOCAL') {
            $sev = 'medium'; if (Test-InWindow $e.TimeCreated) { $sev = 'high' }
            Add-Sys $sev 'remote' 'Remote Desktop session activity (last 24h)' ("event {0} from {1}" -f $e.Id, $addr) $e.TimeCreated 'RDP session log'
        }
    }
    try { foreach ($s in @(Get-SmbSession -ErrorAction Stop)) { Add-Sys 'medium' 'remote' 'Another computer has an SMB session open to this PC' ("{0} ({1})" -f $s.ClientComputerName, $s.ClientUserName) $null 'SMB' } } catch {}
    try { foreach ($m in @(Get-SmbMapping -ErrorAction Stop)) { Add-Sys 'low' 'remote' 'Mapped network drive' ("{0} -> {1}" -f $m.LocalPath, $m.RemotePath) $null 'SMB' } } catch {}
    $k = 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
    if (Test-Path $k) { foreach ($s in @(Get-ChildItem $k -ErrorAction SilentlyContinue)) { Add-Sys 'low' 'remote' 'This account has used Remote Desktop to reach another computer' $s.PSChildName $null 'registry' } }
    try { if ((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections -eq 0) { Add-Sys 'low' 'remote' 'Remote Desktop is enabled on this PC' 'fDenyTSConnections = 0' $null 'registry' } } catch {}
    try {
        $n = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe' -and (Test-PrivateIp ([string]$_.IPAddress)) -and ([string]$_.IPAddress) -notmatch '\.(255|1)$' })
        if ($n.Count -gt 0) { Add-Sys 'low' 'network' 'Other devices are on the same local network (ARP table, count only)' ("{0} device(s)" -f $n.Count) $null 'ARP' }
    } catch {}
}

function Invoke-DnsChecks {
    $entries = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
    if ($entries.Count -eq 0) { Set-ModuleNote 'DNS cache empty/unavailable (cleared recently?)'; return }
    foreach ($d in $entries) {
        $e = [string]$d.Entry
        if ($DnsCheatRx.IsMatch($e)) { Add-Sys 'medium' 'dns' 'A cheat-related domain was looked up recently' $e $null 'DNS cache' }
        elseif ($DnsRemoteRx.IsMatch($e)) { Add-Sys 'low' 'dns' 'A remote-access service domain was looked up recently' $e $null 'DNS cache' }
    }
}

function Invoke-BrowserChecks {
    $browserPaths = @(
        @{ Name = 'Google Chrome'; Dir = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') },
        @{ Name = 'Microsoft Edge'; Dir = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') },
        @{ Name = 'Brave';          Dir = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data') }
    )

    $tempHistDir = Join-Path $env:TEMP 'CactusHacksDetector_hist'
    try { if (-not (Test-Path -LiteralPath $tempHistDir)) { [void](New-Item -ItemType Directory -Path $tempHistDir -Force) } } catch {}

    $cheatDomainRx = '(?i)(liquidbounce|wurstclient|meteorclient|aristois|vape\.gg|futureclient|rusherhack|thunderhack|pandaware|asteria|doomsdayclient|3arthh4ck|salhack|bleachhack|sigmaclient|novoline|exhibitionclient|astolfo|ravenb|fdpclient|tenacity|riseclient|slinky|dortware|augustusclient|xuluclient|boze|opai|cheatengine|autoclicker|blackspigot|directleaks|nulled\.to|cracked\.to|unknowncheats)'
    $cheatKwRx = '(?i)(minecraft[\s+_-]*(cheat|hack|killaura|reach|autoclicker|triggerbot|velocity|nofall|scaffold|esp|xray)|buy[\s+_-]*vape|download[\s+_-]*liquidbounce|download[\s+_-]*meteor)'

    foreach ($b in $browserPaths) {
        if (-not (Test-Path -LiteralPath $b.Dir)) { continue }
        $profiles = @(Get-ChildItem -LiteralPath $b.Dir -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })
        foreach ($p in $profiles) {
            $histFile = Join-Path $p.FullName 'History'
            if (-not (Test-Path -LiteralPath $histFile)) { continue }

            $destFile = Join-Path $tempHistDir ("hist_{0}_{1}_{2}.db" -f ($b.Name -replace '\s+', ''), $p.Name, [Guid]::NewGuid().ToString().Substring(0, 8))
            $ok = $false
            try {
                $srcStream = [System.IO.File]::Open($histFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $destStream = [System.IO.File]::Create($destFile)
                $srcStream.CopyTo($destStream)
                $destStream.Close()
                $srcStream.Close()
                $ok = $true
            } catch {}

            if (-not $ok -or -not (Test-Path -LiteralPath $destFile)) { continue }

            try {
                $bytes = [System.IO.File]::ReadAllBytes($destFile)
                $str = [System.Text.Encoding]::UTF8.GetString($bytes)

                $matches = [regex]::Matches($str, '(?i)[A-Za-z]:\\[^"''<>|:*?\r\n\x00-\x1F]+\.(jar|zip|rar|exe|dll)\b')
                foreach ($m in ($matches | Select-Object -First 60)) {
                    $dlPath = $m.Value.Trim()
                    $leaf = Split-Path -Leaf $dlPath
                    $hit = Get-ToolHit $leaf
                    if ($Rx.Clients.IsMatch($leaf) -or $Rx.Modules.IsMatch($leaf) -or ($hit -and $hit.Cat -in 'injector', 'memedit', 'clicker', 'adapter')) {
                        Add-Sys 'high' 'browser-download' 'Browser history records download of cheat/hack file' ("{0} ({1})" -f $leaf, $b.Name) $null 'Chrome/Edge History'
                    } elseif ($hit -and $hit.Cat -eq 'macro') {
                        Add-Sys 'medium' 'browser-download' 'Macro / automation tool was downloaded in the browser' ("{0} ({1})" -f $leaf, $b.Name) $null 'Chrome/Edge History'
                    } elseif ($hit -and $hit.Cat -in 'remote', 'vm', 'debugger', 'wiper') {
                        Add-Sys 'low' 'browser-download' 'General tool download recorded in browser history (not cheating by itself)' ("{0} ({1})" -f $leaf, $b.Name) $null 'Chrome/Edge History'
                    } elseif ($leaf -match '(?i)\.jar$') {
                        $exists = Test-Path -LiteralPath $dlPath
                        if (-not $exists) {
                            Add-Sys 'medium' 'browser-download' 'Mod/Jar was downloaded in browser but is now deleted or missing' ("{0} ({1})" -f $dlPath, $b.Name) $null 'Chrome/Edge History'
                        } else {
                            Add-Sys 'low' 'browser-download' 'Jar file download recorded in browser history' ("{0} ({1})" -f $leaf, $b.Name) $null 'Chrome/Edge History'
                        }
                    }
                }

                $urlMatches = [regex]::Matches($str, 'https?://[a-zA-Z0-9_\-.]+[a-zA-Z0-9/_\-.?&=%#]+')
                foreach ($um in ($urlMatches | Select-Object -First 100)) {
                    $u = $um.Value
                    if ($u -match $cheatDomainRx) {
                        Add-Sys 'high' 'browser-history' 'Visited known Minecraft cheat / hack site' ("{0} ({1})" -f $u, $b.Name) $null 'Browser History'
                    } elseif ($u -match $cheatKwRx) {
                        Add-Sys 'medium' 'browser-history' 'Searched for or visited Minecraft cheat/hack URL' ("{0} ({1})" -f (Limit-Text $u 90), $b.Name) $null 'Browser History'
                    }
                }
            } catch {}
            finally {
                try { Remove-Item -LiteralPath $destFile -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    }
}

function Invoke-ModDevDeletionsCheck {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -ne 'Fixed' -and $d.DriveType -ne 'Removable') { continue }
        $dir = Join-Path $d.RootDirectory.FullName ('$Recycle.Bin\' + $sid)
        $items = @()
        try { $items = @(Get-ChildItem -LiteralPath $dir -Force -Filter '$I*' -File -ErrorAction Stop) } catch { continue }
        foreach ($f in $items) {
            try {
                $b = [IO.File]::ReadAllBytes($f.FullName)
                if ($b.Length -lt 28) { continue }
                $ver = [BitConverter]::ToInt64($b, 0)
                $ft = [BitConverter]::ToInt64($b, 16)
                $when = [DateTime]::FromFileTimeUtc($ft)
                if ($ver -eq 2) { $len = [BitConverter]::ToInt32($b, 24); $take = [math]::Min($len * 2, $b.Length - 28); $path = [Text.Encoding]::Unicode.GetString($b, 28, [math]::Max(0, $take)).TrimEnd([char]0) }
                else { $take = [math]::Min(520, $b.Length - 24); $path = [Text.Encoding]::Unicode.GetString($b, 24, [math]::Max(0, $take)).TrimEnd([char]0) }
                $leaf = $path -replace '^.*[\\/]', ''
                $ext = Get-Ext $leaf

                if ($path -match '(?i)[\\/](src[\\/]main[\\/]java|build[\\/]libs|fabric\.mod\.json|mods\.toml|\.gradle|gradlew|workspace|mc-mod|cheat-mod|mod-src)') {
                    Add-Sys 'medium' 'mod-dev-deleted' 'Custom mod development / source files were deleted and placed in Recycle Bin' $path $when 'Recycle Bin'
                } elseif ($ext -eq '.jar' -and $path -match '(?i)[\\/](mods|build|libs|target|out|desktop|downloads)[\\/]') {
                    Add-Sys 'medium' 'mod-dev-deleted' 'Minecraft mod jar was recently deleted to Recycle Bin (possible custom mod attempt)' $path $when 'Recycle Bin'
                }
            } catch {}
        }
    }

    $ideaRecent = Join-Path $env:APPDATA 'JetBrains'
    if (Test-Path -LiteralPath $ideaRecent) {
        try {
            $xmls = @(Get-ChildItem -LiteralPath $ideaRecent -Filter 'recentProjects.xml' -Recurse -File -Depth 3 -ErrorAction SilentlyContinue)
            foreach ($x in $xmls) {
                $content = Read-TextFileSafe $x.FullName 1MB
                if ($content -match '(?i)(fabric|forge|quilt|killaura|reach|cheat|hack|disabler)') {
                    Add-Sys 'medium' 'mod-dev' 'Java/IDE recent project history references Minecraft mod or cheat development' (Limit-Text $x.FullName 120) $x.LastWriteTimeUtc 'JetBrains recent'
                }
            }
        } catch {}
    }
}

function Test-StartupItem([string]$Name, [string]$Value, [string]$Source) {
    $hay = "$Name $Value"
    $hit = Get-ToolHit $hay
    if ($Rx.Clients.IsMatch($hay)) { Add-Sys 'high' 'startup' 'Startup entry for a cheat client' $hay $null $Source; return }
    if ($hit -and $hit.Cat -notin 'peripheral', 'sniffer') { Add-Sys $hit.Sev 'startup' ('Startup entry: ' + $hit.Rule) $hay $null $Source; return }
    if ($Value -match '(?i)[\\/](Temp|Downloads|Users[\\/]Public)[\\/]|powershell[^|]*-enc') { Add-Sys 'medium' 'startup' 'Startup entry runs from a temp/download folder or encoded PowerShell' $hay $null $Source }
}

function Invoke-StartupChecks {
    foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
        if (-not (Test-Path $k)) { continue }
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        foreach ($pn in $p.PSObject.Properties) { if ($pn.Name -notlike 'PS*') { Test-StartupItem $pn.Name ([string]$pn.Value) 'Run key' } }
    }
    foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
        if ($d -and (Test-Path -LiteralPath $d)) { foreach ($f in @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue)) { Test-StartupItem $f.Name $f.FullName 'Startup folder' } }
    }
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
            $acts = ((@($t.Actions) | ForEach-Object { "{0} {1}" -f $_.Execute, $_.Arguments }) -join ' ; ')
            $hit = Get-ToolHit "$($t.TaskName) $acts"
            if ($Rx.Clients.IsMatch($acts) -or ($hit -and $hit.Cat -notin 'peripheral', 'sniffer') -or $acts -match '(?i)powershell[^;]*-enc|\.ahk') {
                Add-Sys 'medium' 'startup' 'Scheduled task runs a suspicious program' ("{0}: {1}" -f $t.TaskName, $acts) $null 'Task Scheduler'
            } elseif ($t.Date -and (Test-InWindow ([string]$t.Date))) {
                Add-Sys 'low' 'startup' 'A scheduled task was created inside the lookback window' ("{0}: {1}" -f $t.TaskName, $acts) $null 'Task Scheduler'
            }
        }
    } catch {}
    try {
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
            $hay = "$($s.Name) $($s.DisplayName) $($s.PathName)"
            $hit = Get-ToolHit $hay
            if ($hit -and $hit.Cat -in 'injector', 'memedit', 'clicker', 'adapter', 'wiper', 'remote') { Add-Sys $hit.Sev 'startup' ('Service: ' + $hit.Rule) ("{0} ({1})" -f $s.Name, $s.State) $null 'services' }
        }
    } catch {}
}

function Invoke-DriverChecks {
    $drvRx = New-Object Regex('(?i)(capcom|(?<![a-z])gdrv\.sys\b|(?<![a-z])gdrv(?![a-z])|iqvw64e|rtcore64|dbutil_?2_?3|asrdrv|physmem|winring0|cpuz|(?<![a-z])ene\.sys|glckio2|atillk64|asmmap64|(?<![a-z])asio(?![a-z])|mhyprot|kprocesshacker|dbk(32|64)|speedfan|(?<![a-z])hw64|nvflash|inpoutx64|rwdrv|kdmapper|(?<![a-z])nal\.sys|ntiolib|phymemx64)', 'Compiled')
    try {
        foreach ($d in @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop)) {
            $hay = "$($d.Name) $($d.PathName)"

            if ($hay -match '(?i)\behstortcgdrv\b|ehstor') { continue }
            if ($drvRx.IsMatch($hay)) {
                $sev = 'low'; $rule = 'A driver abused by cheat tools is installed (also used by legitimate hardware tools)'
                if ($hay -match '(?i)dbk(32|64)') { $sev = 'high'; $rule = 'Cheat Engine kernel driver is installed' }
                elseif ($hay -match '(?i)kprocesshacker') { $sev = 'medium'; $rule = 'Process Hacker kernel driver is installed' }
                Add-Sys $sev 'driver' $rule ("{0} ({1})" -f $d.Name, $d.State) $null 'drivers'
            }
        }
    } catch {}
    if ($script:IsAdmin) {
        $bc = @(& bcdedit.exe /enum '{current}' 2>$null)
        foreach ($l in $bc) {
            $s = [string]$l
            if ($s -match '^\s*(testsigning|nointegritychecks)\s+(\S+)' -and $Matches[2] -notmatch '(?i)^(no|nein|non|nao|off)$') { Add-Sys 'high' 'driver' 'Driver signature enforcement is weakened (test-signing / integrity checks off)' (Limit-Text $s 80) $null 'bcdedit' }
            elseif ($s -match '(?i)^\s*loadoptions\s+.*DISABLE_INTEGRITY_CHECKS') { Add-Sys 'high' 'driver' 'Driver signature enforcement is disabled (loadoptions)' (Limit-Text $s 80) $null 'bcdedit' }
            elseif ($s -match '^\s*debug\s+(\S+)' -and $Matches[1] -notmatch '(?i)^(no|nein|non|nao|off)$') { Add-Sys 'medium' 'driver' 'Kernel debugging is enabled' (Limit-Text $s 80) $null 'bcdedit' }
        }
        try { if (-not (Confirm-SecureBootUEFI -ErrorAction Stop)) { Add-Sys 'low' 'driver' 'Secure Boot is off' '' $null 'firmware' } } catch {}
    } else { Set-ModuleNote 'partial: boot-configuration checks need Administrator' }
    try {
        $v = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -ErrorAction Stop).VulnerableDriverBlocklistEnable
        if ($null -ne $v -and [int]$v -eq 0) { Add-Sys 'medium' 'driver' 'The Windows vulnerable-driver blocklist is turned off' 'VulnerableDriverBlocklistEnable = 0' $null 'registry' }
    } catch {}
}

function Invoke-PipeChecks {
    $pipes = @()
    try { $pipes = @([IO.Directory]::GetFiles('\\.\pipe\')) } catch { return }
    foreach ($p in $pipes) {
        $n = $p -replace '^\\\\\.\\pipe\\', ''
        if ($Rx.Clients.IsMatch($n) -or $Rx.Modules.IsMatch($n) -or $n -match '(?i)(aimbot|cheat|injector)') { Add-Sys 'medium' 'process' 'Named pipe with a cheat-like name' $n $null 'named pipes' }
    }
}

function Invoke-InstalledSoftwareChecks {
    foreach ($r in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        foreach ($i in @(Get-ItemProperty $r -ErrorAction SilentlyContinue)) {
            $n = [string]$i.DisplayName
            if (-not $n) { continue }
            $hit = Get-ToolHit $n
            if ($Rx.Clients.IsMatch($n)) { Add-Sys 'high' 'software' 'Cheat client is installed' $n $null 'installed programs' }
            elseif ($hit) {
                $sev = 'low'; if ($hit.Cat -in 'injector', 'memedit', 'clicker', 'adapter', 'wiper') { $sev = 'medium' }
                Add-Sys $sev 'software' ('Installed: ' + $hit.Rule) $n $null 'installed programs'
            }
        }
    }
}

$script:BadHashes = @{}

function Get-ModClass($m) {
    $v = [string]$m.Verdict
    if ($v -like '*verified hash*') { return 'FP' }
    if ($v -like 'MALWARE*') { return 'MALWARE' }
    if ($v -like 'CHEAT*') { return 'CHEAT' }
    if ($v -like 'SUSPICIOUS*') { return 'SUSPICIOUS' }
    if ($v -like 'VERIFIED*') { return 'VERIFIED' }
    return 'CLEAN'
}

function Get-SevRank([string]$s) { switch ($s) { 'high' { 3 } 'medium' { 2 } 'low' { 1 } default { 0 } } }

$script:CheaterTrollMessages = @(
    'Bro installed Fly just to audition for the Minecraft Aviation Academy.',
    'Flying? Wanted to be a bird so badly, forgot this is survival mode.',
    'Your wings are rented. Gravity would like them back.',
    'Bro thinks he''s a creative-mode tourist.',
    'That fly hack won''t help you land a personality.',
    'Imagine downloading the ability to fall upward.',
    'Scaffold detected. Building skills still loading?',
    'Bro can''t place blocks without a construction assistant.',
    'Your bridge has more support than your argument.',
    'Scaffold doing all the architecture while you supervise.',
    'Bro hired an automated builder for a dirt bridge.',
    'Can''t build a staircase without technological assistance. Tragic.',
    'KillAura on? Bro''s mouse is fighting the entire server.',
    'Your crosshair is on vacation and your aura is working overtime.',
    'Bro attacks everyone except the idea of learning PvP.',
    'KillAura: because choosing a target manually is apparently advanced.',
    'Your mouse is spinning like it owes somebody money.',
    'Bro turned PvP into an automatic group project.',
    'Reach hack? Trying to hit people from another postcode?',
    'Bro''s arms are apparently sponsored by elastic technology.',
    'That hit travelled farther than the server''s player count.',
    'Reach so long it needs its own postal address.',
    'Bro is fighting from a different time zone.',
    'Your sword has a telescopic attachment now?',
    'AutoClicker detected. So nub you outsourced left-clicking.',
    'Bro couldn''t left-click at the right time, so hired a robot.',
    'Your mouse is clicking harder than you are thinking.',
    'Imagine needing automation for the button labelled attack.',
    'Those clicks are more scheduled than a school timetable.',
    'Your finger filed for unemployment.',
    'Speed hack? Bro drank twelve stacks of sugar.',
    'Running that fast just to escape the skill issue.',
    'Bro is moving like the floor is lava and rent is due.',
    'Speed so suspicious even the chunks are confused.',
    'Your legs have a software update, apparently.',
    'X-ray enabled. Mining with Google Maps now?',
    'Bro can''t find diamonds without seeing through the planet.',
    'Your mining strategy is just geological cheating.',
    'X-ray vision but still can''t see the consequences.',
    'Even the diamonds are embarrassed for you.',
    'Anti-knockback? Bro is emotionally unavailable to physics.',
    'Knockback said hello and you left it on read.',
    'Your character has the stability of a parked refrigerator.',
    'Physics tried to move you. Your client said no.',
    'Jesus couldn''t move this player''s knockback resistance.',
    'Velocity off? Bro is allergic to consequences.',
    'Criticals hack? Every hit comes with a suspicious little jump.',
    'Bro needs software to remember how gravity works.',
    'AutoTotem? Your inventory has a personal assistant.',
    'Inventory management outsourced. What a career.',
    'Bro''s totem swaps faster than their brain processes danger.',
    'ChestStealer? Can''t even loot a chest without automation.',
    'Your hands are on spectator mode while the client does chores.',
    'FastPlace? Bro is speedrunning the building department.',
    'Your blocks are arriving before your thoughts.',
    'Jesus built the world in six days. You need a module for one wall.',
    'BunnyHop? Bro thinks the server is a trampoline park.',
    'Jumping like a rabbit, playing like a potato.',
    'Your knees have more macros than movement skills.',
    'Phase hack? Trying to become one with the wall?',
    'Bro wants to live inside the blocks rent-free.',
    'Clip through walls, still can''t clip into the skill leaderboard.',
    'Freecam? Even your camera is trying to leave the match.',
    'Your body stayed here but your dignity went scouting.',
    'Jesus take the wheel, this player can''t steer manually.',
    'Derp mode? Your character looks like a broken ceiling fan.',
    'Spinbot detected. Bro is buffering in real life.',
    'Your head is rotating like it''s searching for Wi-Fi.',
    'Anti-aim? The only thing you''re dodging is practice.',
    'AutoArmor? Getting dressed by a computer is crazy.',
    'Bro needs an assistant to put on a helmet.',
    'FastEat? Even your lunch is being speedrun.',
    'Your food has a faster reaction time than you.',
    'Timer hack? Bro wants extra hours in a block game.',
    'Playing at 2x speed won''t double your skill.',
    'Blink hack? Bro''s connection to fair play keeps disconnecting.',
    'Packet tricks? Your excuses have better networking than you.',
    'Disabler? Trying to disable the consequences too?',
    'Jesus, even your cheat client needs a cheat client.',
    'Baritone? Can''t walk to a destination without GPS and autopilot.',
    'Bro put Minecraft on self-driving mode.',
    'Pathfinding harder than finding a legit excuse.',
    'AutoFish? Can''t even wait for a pixel to bite.',
    'Fishing with a robot. The fish are still smarter.',
    'ESP enabled. Seeing players through walls but not your own mistakes.',
    'Tracers on? Bro needs subtitles for nearby enemies.',
    'NameTags through walls? Mind your own coordinates.',
    'Your client knows where everyone is except where your skill went.',
    'FastBreak? Breaking blocks faster than you''re breaking server rules.',
    'Your pickaxe has a suspicious work ethic.',
    'Jesus, that block barely got time to exist.',
    'AutoSoup? Even your healing has a manager.',
    'Regen hack? Your health bar has a subscription plan.',
    'You''re not immortal. You''re just temporarily embarrassing.',
    'Botting? Even your account has more free time than you.',
    'Imagine letting a bot play the game you logged in to play.',
    'Your keyboard is just a decorative accessory at this point.',
    'Rethink your life decisions. It''s a block game, not a job interview.',
    'Anticheat caught you. Your disguise had one job.',
    'Bro got exposed by a rectangle with a sword.'
)

$script:LegitPlayerMessages = @(
    'THIS PLAYER IS A GOAT. REAL SKILL STILL EXISTS.',
    'Legit players are still alive. Nature is healing.',
    'Clean gameplay. Clean hands. Massive respect.',
    'No hacks, no excuses, just good Minecraft.',
    'Bro is winning with pure skill. Rare sighting.',
    'An actual player, not a walking cheat menu.',
    'Respect. This one earned every hit.',
    'Legit detected. Everybody stay calm.',
    'Finally, someone who lets their mouse do the work.',
    'Certified fair-play legend.',
    'That aim is handcrafted, not downloaded.',
    'Clean clicks and cleaner gameplay.',
    'Proof that you don''t need hacks to be cracked.',
    'An honest player in this economy? Legendary.',
    'Bro brought skill instead of a settings folder.',
    'Fair fight. Massive W.',
    'Someone give this player a medal and a new mousepad.',
    'Legit gameplay goes unbelievably hard.',
    'Not cheating, just built different.',
    'Respect the grind. No shortcuts detected.',
    'Bro is playing Minecraft, not configuring NASA.',
    'Clean movement. Cleaner reputation.',
    'That combo was 100% home-grown.',
    'Rare footage of a player using actual hands.',
    'Skill issue? Not on this player''s side.',
    'Legit player spotted. Protect this species.',
    'Bro doesn''t need a cheat client to be dangerous.',
    'Honest clicks. Dishonest levels of skill.',
    'Someone cooked, and it wasn''t an autoclicker.',
    'That was clean enough to disinfect the server.',
    'Fair-play department approves this message.',
    'Bro passed the vibe check and the anticheat check.',
    'Mouse movements powered by actual effort.',
    'An endangered species: the legit Minecraft player.',
    'Real skill, no suspicious extras.',
    'Bro fights with courage and a normal client.',
    'Respect. The only thing injected here was confidence.',
    'That clutch deserves a replay.',
    'Clean player, dirty combo.',
    'Legit confirmed. We can all go home.',
    'Bro''s only advantage is being better.',
    'Absolutely no hacks, just premium talent.',
    'That was a skill issue for the opponent.',
    'Someone is making the leaderboard look honest.',
    'Fair play never looked this disrespectful.',
    'Bro is proof that practice still works.',
    'Not a single suspicious setting in sight.',
    'Clean PvP. Even the replay is impressed.',
    'An honest warrior has entered the arena.',
    'That''s what happens when you learn the game.',
    'Legit player: 1. Excuses: 0.',
    'Bro''s mouse has a gym membership.',
    'Every hit manually delivered. Respect.',
    'Finally, a player who doesn''t need a tutorial for toggling hacks.',
    'Skill so clean it came with a receipt.',
    'Bro is farming wins, not settings.',
    'Good movement, good aim, good sportsmanship.',
    'That was a fair fight and an unfair beating.',
    'Legit players make the server worth playing.',
    'Someone actually learned their clicks. Incredible.',
    'Clean enough to be an anticheat advertisement.',
    'Bro is running on skill.exe.',
    'Respect the player, not the ping.',
    'That combo had no third-party assistance.',
    'One client, two hands, unlimited talent.',
    'Bro''s secret weapon is practice. Disgusting.',
    'An actual Minecraft player has been discovered.',
    'Nothing suspicious here except that confidence.',
    'Fair play with a side of absolute destruction.',
    'That was a clean sweep.',
    'Bro didn''t toggle anything except W.',
    'Legit and lethal. In the PvP sense.',
    'Skill issue detected on the other team.',
    'Someone cooked without opening a config menu.',
    'Clean clicks are back in fashion.',
    'Bro is the reason anticheat can take a lunch break.',
    'That win was earned the old-fashioned way.',
    'Respect. The mouse is doing honest work.',
    'Legit gameplay? In this server? Beautiful.',
    'Bro''s aim is not on a subscription plan.',
    'Fair fight, fantastic result.',
    'Clean movement deserves loud applause.',
    'An honest player with villain-level combos.',
    'That''s not a hack. That''s a highlight.',
    'Bro is carrying the server''s reputation.',
    'One hundred percent legit energy.',
    'Actual talent has entered the chat.',
    'Keep playing like that. The server needs it.',
    'Bro is built from practice and bad intentions.',
    'Fair play, maximum disrespect.',
    'Clean PvP is a beautiful thing.',
    'Not even the replay can find anything suspicious.',
    'Legit player spotted. Rare drop unlocked.',
    'Bro made that look effortless.',
    'Skill is the only thing being abused here.',
    'Respect. No shortcuts, no excuses.',
    'That''s a certified fair-play W.',
    'Bro''s hands deserve their own rank.',
    'Real players still exist. We have evidence.',
    'Clean client, dirty work.'
)

$script:SuspectTrollMessages = @(
    'NUB: You are on thin ice, and we have got a magnifying glass [!] (nub behavior detected)',
    'NUB: Something smells fishy... We see those reach circle / weird tweaks, nub',
    'NUB: Not fully caught yet, but your client is looking questionable [?]',
    'NUB: Bro is walking a very fine line between ''good gaming chair'' and ''banned''',
    'NUB: Suspicious modifications detected. The staff team is watching you, nub'
)

function Get-TrollMessage([string]$Category, [string[]]$Hacks, [object]$AiCheatResult) {
    if ($Category -eq 'chad') {
        return ($script:LegitPlayerMessages | Get-Random)
    }
    if ($Category -eq 'suspect') {
        return ($script:SuspectTrollMessages | Get-Random)
    }

    if ($AiCheatResult -and $AiCheatResult.verdict -eq 'CHEAT') {
        $modName = if ($AiCheatResult.file) { $AiCheatResult.file } else { 'custom mod' }
        $hName = if ($AiCheatResult.hack_name -and $AiCheatResult.hack_name -ne 'None') { $AiCheatResult.hack_name } else { 'cheat code' }
        $sum = if ($AiCheatResult.troll_summary) { $AiCheatResult.troll_summary } else { 'AI exposed hidden cheats in this mod' }
        return "Bro thought he could hide his skill issues with a custom mod! AI inspected '$modName' and exposed: $hName ($sum)"
    }

    $hackStr = ($Hacks -join ' ').ToLower()
    if ($hackStr -match 'shield.*disabl|disabl.*shield|disabler') {
        return 'Shield Disabler caught: Bro was so terrified of a wooden shield that he wrote an entire disabler for it! Zero sword skills detected.'
    }
    if ($hackStr -match 'shield.*indicat|reach.*circle|reach.*indicat') {
        return 'Bro has a whole HUD indicator just to tell if someone is holding right-click! Skill issues detected.'
    }

    if ($hackStr -match 'fly|flight') { return ($script:CheaterTrollMessages[0..5] | Get-Random) }
    if ($hackStr -match 'scaffold') { return ($script:CheaterTrollMessages[6..11] | Get-Random) }
    if ($hackStr -match 'aura|killaura') { return ($script:CheaterTrollMessages[12..17] | Get-Random) }
    if ($hackStr -match 'reach') { return ($script:CheaterTrollMessages[18..23] | Get-Random) }
    if ($hackStr -match 'clicker|autoclicker|cps') { return ($script:CheaterTrollMessages[24..29] | Get-Random) }
    if ($hackStr -match 'speed') { return ($script:CheaterTrollMessages[30..34] | Get-Random) }
    if ($hackStr -match 'xray|x-ray') { return ($script:CheaterTrollMessages[35..39] | Get-Random) }
    if ($hackStr -match 'velocity|knockback|antikb') { return ($script:CheaterTrollMessages[40..45] | Get-Random) }
    if ($hackStr -match 'critical') { return ($script:CheaterTrollMessages[46..47] | Get-Random) }
    if ($hackStr -match 'totem|autototem') { return ($script:CheaterTrollMessages[48..50] | Get-Random) }
    if ($hackStr -match 'chest|steal') { return ($script:CheaterTrollMessages[51..52] | Get-Random) }
    if ($hackStr -match 'fastplace|fast') { return ($script:CheaterTrollMessages[53..55] | Get-Random) }
    if ($hackStr -match 'bhop|bunny') { return ($script:CheaterTrollMessages[56..58] | Get-Random) }
    if ($hackStr -match 'phase') { return ($script:CheaterTrollMessages[59..61] | Get-Random) }
    if ($hackStr -match 'freecam') { return ($script:CheaterTrollMessages[62..63] | Get-Random) }
    if ($hackStr -match 'spin|derp|anti-aim|antiaim') { return ($script:CheaterTrollMessages[65..68] | Get-Random) }
    if ($hackStr -match 'armor|autoarmor') { return ($script:CheaterTrollMessages[69..70] | Get-Random) }
    if ($hackStr -match 'eat|fasteat') { return ($script:CheaterTrollMessages[71..72] | Get-Random) }
    if ($hackStr -match 'timer') { return ($script:CheaterTrollMessages[73..74] | Get-Random) }
    if ($hackStr -match 'blink') { return ($script:CheaterTrollMessages[75..76] | Get-Random) }
    if ($hackStr -match 'baritone|path') { return ($script:CheaterTrollMessages[79..81] | Get-Random) }
    if ($hackStr -match 'esp|tracer|nametag') { return ($script:CheaterTrollMessages[84..87] | Get-Random) }
    if ($hackStr -match 'bot|botting|macro') { return ($script:CheaterTrollMessages[94..96] | Get-Random) }

    return ($script:CheaterTrollMessages | Get-Random)
}

function Show-CheaterAnimation($PlayerName, [int]$Score, $Hacks, $Reasons, $TrollMsg, $AiResult) {
    Write-Host ''
    for ($i = 0; $i -lt 2; $i++) {
        Write-Host "  >>> ALERT: CHEAT DETECTED <<<" -ForegroundColor Red
        Start-Sleep -Milliseconds 100
    }
    Write-Host ''
    $art = @(
        '   _____          _    _  _____  _    _  _______  _ ',
        '  / ____|   /\   | |  | |/ ____|| |  | ||__   __|| |    CAUGHT!',
        ' | |       /  \  | |  | | |  __ | |__| |   | |   | |',
        ' | |      / /\ \ | |  | | | |_ ||  __  |   | |   | |    CHEATER!',
        ' | |____ / ____ \| |__| | |__| || |  | |   | |   |_|',
        '  \_____/_/    \_| \____/ \_____||_|  |_|   |_|   (_)'
    )
    foreach ($line in $art) {
        Write-Host $line -ForegroundColor Red
        Start-Sleep -Milliseconds 40
    }
    Write-Host ''
    Write-Host "  ==========================================================================" -ForegroundColor Red
    Write-Host ("  PLAYER:  {0}" -f $PlayerName) -ForegroundColor White
    Write-Host ("  VERDICT: CHEATER ({0}% CHEATING)" -f $Score) -ForegroundColor Red
    Write-Host "  ==========================================================================" -ForegroundColor Red

    $hackNames = @($Hacks | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.Name } } | Select-Object -Unique)
    if ($hackNames.Count -gt 0) {
        Write-Host ''
        Write-Host "  [!] CAUGHT YOU USING:" -ForegroundColor Red
        foreach ($h in ($hackNames | Select-Object -First 8)) {
            Write-Host ("      * {0}" -f $h) -ForegroundColor Yellow
        }
    }

    if ($AiResult -and $AiResult.verdict -eq 'CHEAT') {
        Write-Host ''
        Write-Host "  [CACTUS AI MOD INSPECTION]:" -ForegroundColor Magenta
        Write-Host ("      Mod: {0}" -f $AiResult.file) -ForegroundColor Cyan
        Write-Host ("      AI Verdict: CHEAT ({0}% confidence)" -f $AiResult.cheating_score) -ForegroundColor Red
        Write-Host ("      AI Explanation: {0}" -f $AiResult.troll_summary) -ForegroundColor Gray
    }

    Write-Host ''
    Write-Host ("  [!] {0}" -f $TrollMsg) -ForegroundColor Yellow
    Write-Host "  ==========================================================================" -ForegroundColor Red
    Write-Host ''
}

function Show-SuspectAnimation($PlayerName, [int]$Score, $Hacks, $Reasons, $TrollMsg, $AiResult) {
    Write-Host ''
    $art = @(
        '  _   _ _   _ ____  _ ',
        ' | \ | | | | |  _ \| |',
        ' |  \| | | | | |_) | |   NUB ALERT!',
        ' | . ` | | | |  _ <| |   QUESTIONABLE TWEAKS...',
        ' | |\  | |_| | |_) |_|',
        ' |_| \_|\___/|____/(_)'
    )
    foreach ($line in $art) {
        Write-Host $line -ForegroundColor Yellow
        Start-Sleep -Milliseconds 30
    }
    Write-Host ''
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host ("  PLAYER:  {0}" -f $PlayerName) -ForegroundColor White
    Write-Host ("  STATUS:  NUB ALERT ({0}% SUSPICIOUS)" -f $Score) -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Yellow

    if ($Reasons.Count -gt 0) {
        Write-Host ''
        Write-Host "  [?] NUB FINDINGS:" -ForegroundColor Yellow
        foreach ($r in ($Reasons | Select-Object -First 4)) {
            Write-Host ("      * {0}" -f $r) -ForegroundColor DarkYellow
        }
    }

    if ($AiResult) {
        Write-Host ''
        Write-Host "  [CACTUS AI MOD INSPECTION]:" -ForegroundColor Magenta
        Write-Host ("      Mod: {0} -> AI Verdict: {1} ({2}%)" -f $AiResult.file, $AiResult.verdict, $AiResult.cheating_score) -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host ("  [?] {0}" -f $TrollMsg) -ForegroundColor Yellow
    Write-Host "  --------------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host ''
}

function Show-ChadAnimation($PlayerName, [int]$Score, $TrollMsg) {
    Write-Host ''
    $art = @(
        '   _____  _    _            _____   _ ',
        '  / ____|| |  | |   /\     |  __ \ | |    LEGIT PLAYER DETECTED!',
        ' | |     | |__| |  /  \    | |  | || |    REAL SKILL. NO SHORTCUTS.',
        ' | |     |  __  | / /\ \   | |  | || |    CERTIFIED CHAD (LEGIT).',
        ' | |____ | |  | |/ ____ \  | |__| ||_|',
        '  \_____||_|  |_/_/    \_\|_____/ (_)'
    )
    foreach ($line in $art) {
        Write-Host $line -ForegroundColor Green
        Start-Sleep -Milliseconds 25
    }
    Write-Host ''
    Write-Host "  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -ForegroundColor Green
    Write-Host ("  PLAYER:  {0}" -f $PlayerName) -ForegroundColor White
    Write-Host ("  VERDICT: 100% NOT CHEATING (CERTIFIED CHAD)" -f (100 - $Score)) -ForegroundColor Green
    Write-Host "  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -ForegroundColor Green
    Write-Host ''
    Write-Host ("  [+] {0}" -f $TrollMsg) -ForegroundColor Green
    Write-Host "  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" -ForegroundColor Green
    Write-Host ''
}

function Start-AiModInspection([object[]]$CandidateMods, [string]$ApiKey, [string]$Model) {
    return $null
}

function Wait-AiModInspection($Job) {
    return @()
}

function Apply-AiResultsToMods($Mods, $AiResults) {
    if (-not $AiResults -or @($AiResults).Count -eq 0) { return }
    $aiMap = @{}
    foreach ($r in $AiResults) { if ($r.file) { $aiMap[$r.file.ToLower()] = $r } }
    foreach ($m in $Mods) {
        $fLower = $m.File.ToLower()
        if ($aiMap.ContainsKey($fLower)) {
            $ai = $aiMap[$fLower]
            if ($m.Legit -and $ai.verdict -eq 'SUSPECT' -and ([string]$ai.category -eq 'ADVANTAGE_MOD' -or [int]$ai.cheating_score -lt 50)) {
                $ai.verdict = 'CHAD'
                $ai.category = 'CLEAN'
                $ai.cheating_score = [math]::Min(10, [int]$ai.cheating_score)
                if ($m.Verdict -notlike 'CHEAT*' -and $m.Verdict -notlike 'MALWARE*') { $m.Verdict = 'VERIFIED (legit tool: ' + $m.Legit + ')' }
                continue
            }
            if ($ai.verdict -eq 'CHEAT') {
                $m.Score = [math]::Max([int]$m.Score, [int]$ai.cheating_score)
                $m.Verdict = 'CHEAT (AI Detected)'
                $m.Findings = @($m.Findings) + [pscustomobject]@{ Severity = 'high'; Category = 'ai-inspection'; Rule = "AI detected cheat: $($ai.hack_name)"; Detail = $ai.troll_summary; Where = $m.File }
            } elseif ($ai.verdict -eq 'SUSPECT') {
                $m.Score = [math]::Max([int]$m.Score, [int]$ai.cheating_score)
                if ($m.Verdict -notin 'CHEAT', 'MALWARE') { $m.Verdict = 'SUSPICIOUS (AI Flagged)' }
                $m.Findings = @($m.Findings) + [pscustomobject]@{ Severity = 'medium'; Category = 'ai-inspection'; Rule = "AI flagged as nub"; Detail = $ai.troll_summary; Where = $m.File }
            } elseif ($ai.verdict -eq 'CHAD') {
                if ($m.Verdict -notin 'CHEAT', 'MALWARE', 'SUSPICIOUS') { $m.Verdict = 'VERIFIED (AI Clean)' }
            }
        }
    }
}

$StrongSystemRx = New-Object Regex('(?i)cheat[ -]?client|cheat mod|cheat-named|cheat/hack|hack[- ]module|hack client|game log mentions|injector|memory editor|auto-?clicker|console cheat adapter|macro / automation|macro scripts|clears event logs|event log was cleared|security log was cleared|history saving is switched off|deletes the usn|deletes prefetch|wipes shell history|edits file timestamps|tampers with windows defender', 'Compiled')

function Get-Summary($Mods, $Jvm, $AiResults = @()) {
    $score = 0
    $c = [ordered]@{ modsMalware = 0; modsCheat = 0; modsSuspicious = 0; modsFalsePositive = 0; modsVerified = 0; modsClean = 0; high = 0; medium = 0; low = 0; notes = 0 }
    $reasons = New-Object System.Collections.Generic.List[object]
    foreach ($m in $Mods) {
        $cls = Get-ModClass $m
        $names = ((@($m.Hacks) | Where-Object { $_.Strength -notin 'weak', 'keybinding' } | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', ')
        $extra = ''; if ($names) { $extra = " (hacks: $names)" }
        switch ($cls) {
            'MALWARE'    { $c.modsMalware++;    $score += 60; [void]$reasons.Add(@(4, ("Malware behaviour in mod {0}{1}" -f $m.File, $extra))) }
            'CHEAT'      { $c.modsCheat++;      $score += 40; [void]$reasons.Add(@(3, ("Cheat mod: {0}{1}" -f $m.File, $extra))) }
            'SUSPICIOUS' { $c.modsSuspicious++; $score += 15; [void]$reasons.Add(@(2, ("Suspicious mod: {0}" -f $m.File))) }
            'FP'         { $c.modsFalsePositive++ }
            'VERIFIED'   { $c.modsVerified++ }
            default      { $c.modsClean++ }
        }
    }
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($s in $script:Sys) { [void]$all.Add($s) }
    $nSys = $all.Count
    foreach ($j in $Jvm) { foreach ($f in @($j.Findings)) { [void]$all.Add($f) } }
    $sysTexts = New-Object 'System.Collections.Generic.HashSet[string]'
    $allIdx = 0
    foreach ($f in $all) {
        $isSys = ($allIdx -lt $nSys)
        $allIdx++
        if ($isSys -and -not $StrongSystemRx.IsMatch([string]$f.Rule)) { $c.notes++; continue }
        $rtext = ('{0}: {1}' -f $f.Rule, (Limit-Text $f.Detail 90))
        switch ($f.Severity) {
            'high'   { $c.high++;   $score += 10; [void]$reasons.Add(@(3, $rtext)); if ($isSys) { [void]$sysTexts.Add($rtext) } }
            'medium' { $c.medium++; $score += 4;  [void]$reasons.Add(@(2, $rtext)); if ($isSys) { [void]$sysTexts.Add($rtext) } }
            'low'    { $c.low++;    $score += 1 }
        }
    }

    $aiCheat = $null
    foreach ($ai in $AiResults) {
        if ($ai.verdict -eq 'CHEAT') {
            $c.modsCheat++
            $score += 40
            $aiCheat = $ai
            [void]$reasons.Add(@(4, ("AI flagged mod {0} as CHEAT: {1}" -f $ai.file, $ai.hack_name)))
        } elseif ($ai.verdict -eq 'SUSPECT') {
            $c.modsSuspicious++
            $score += 15
            [void]$reasons.Add(@(2, ("AI flagged mod {0} as NUB: {1}" -f $ai.file, $ai.troll_summary)))
        }
    }

    $verdict = 'NO FINDINGS'
    if ($c.low -gt 0 -or $c.modsFalsePositive -gt 0) { $verdict = 'MINOR NOTES' }
    if ($c.medium -gt 0 -or $c.modsSuspicious -gt 0) { $verdict = 'REVIEW' }
    if ($c.high -gt 0 -or $c.modsCheat -gt 0) { $verdict = 'HIGH RISK' }
    if ($c.modsMalware -gt 0) { $verdict = 'MALWARE FOUND' }
    $sortedReasons = @($reasons | Sort-Object { -[int]$_[0] } | ForEach-Object { [string]$_[1] } | Select-Object -Unique)
    $top = @($sortedReasons | Select-Object -First 10)

    $termTop = @($sortedReasons | Where-Object { -not $sysTexts.Contains([string]$_) } | Select-Object -First 6)

    $allHacks = New-Object System.Collections.Generic.List[string]
    foreach ($m in $Mods) {
        if ([string]$m.File -match '(?i)\.(disabled|old|bak|duplicate|backup|off)$') { continue }
        foreach ($h in @($m.Hacks)) {
            if ($h -and $h.Name -and $h.Kind -ne 'Keybind') { [void]$allHacks.Add($h.Name) }
        }
    }

    $allText = (($reasons -join ' ') + ' ' + ($allHacks -join ' ')).ToLower()
    $cheatByEvidence = ($c.modsMalware -gt 0 -or $c.modsCheat -gt 0)
    $hasConfirmedCheat = ($cheatByEvidence -or ($allText -match '(?i)\b(killaura|kill-aura|crystal[-_]?aura|auto[-_]?crystal|trigger[-_]?bot|silent[-_]?aim|aim[-_]?bot|fly[-_]?hack|speed[-_]?hack|bhop|scaffold(?!ing)|phase[-_]?hack|nofall|wurst|liquidbounce|meteor[-_]?client|future[-_]?client|rusher[-_]?hack|thunder[-_]?hack|vape[-_]?(?:v4|lite))\b'))
    $isMinorAdvantage = ($allText -match '(?i)shield.*indicat|reach.*circle|reach.*indicat|fullbright|freecam|cps|hud|litematica|tweakeroo|mousetweaks|inventoryprofiles')

    $category = 'chad'
    $finalScore = [math]::Min(100, $score)
    if ($cheatByEvidence -or ($hasConfirmedCheat -and -not $isMinorAdvantage)) {
        $category = 'cheater'
        $verdict = if ($c.modsMalware -gt 0) { 'MALWARE FOUND' } else { 'HIGH RISK' }
        $finalScore = [math]::Max(65, $finalScore)
    } elseif ($c.modsSuspicious -gt 0 -or $c.medium -gt 0 -or $isMinorAdvantage -or $allText -match '(?i)keybind|disallowed|policy|unverified|suspicious') {
        $category = 'suspect'
        $verdict = 'REVIEW'

        $finalScore = [math]::Min(45, [math]::Max(15, $finalScore))
    } else {
        $category = 'chad'
        $verdict = if ($c.low -gt 0) { 'MINOR NOTES' } else { 'NO FINDINGS' }
        $finalScore = [math]::Min(10, $finalScore)
    }
    $trollMsg = Get-TrollMessage $category $allHacks $aiCheat

    [ordered]@{
        verdict        = $verdict
        category       = $category
        threatScore    = $finalScore
        cheatingScore  = $finalScore
        displayMessage = $trollMsg
        reasons        = $top
        terminalReasons = $termTop
        counts         = $c
        aiResults      = $AiResults
    }
}

function Format-When($t) {
    if (-not $t) { return '' }
    try { return ([datetime]::Parse([string]$t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime().ToString('MM-dd HH:mm') } catch { return '' }
}

function Get-SevColor([string]$s) { switch ($s) { 'high' { 'Red' } 'medium' { 'Yellow' } default { 'DarkGray' } } }

function Write-FindingLine([string]$Sev, [string]$Rule, [string]$Detail, [string]$When, [string]$Indent = '  ') {
    $label = ('{0}[{1,-6}] ' -f $Indent, $Sev.ToUpper())
    Write-Host $label -NoNewline -ForegroundColor (Get-SevColor $Sev)
    $w = ''; if ($When) { $w = "  ($When)" }
    Write-Host ($Rule + $w) -ForegroundColor White
    if ($Detail) { Write-Host (($Indent + '         ') + $Detail) -ForegroundColor Gray }
}

function Show-Verdict($Summary, $Mods, $AiResults = @()) {
    $cat = $Summary.category
    $pName = if ($script:Accounts -and $script:Accounts.currentAccountName) { $script:Accounts.currentAccountName } else { 'Player' }
    $hList = New-Object System.Collections.Generic.List[string]
    foreach ($m in $Mods) {
        if ([string]$m.File -match '(?i)\.(disabled|old|bak|duplicate|backup|off)$') { continue }
        foreach ($h in @($m.Hacks)) { if ($h -and $h.Kind -ne 'Keybind') { [void]$hList.Add($h.Name) } }
    }
    $aiCheatFirst = if ($AiResults) { @($AiResults | Where-Object { $_.verdict -eq 'CHEAT' } | Select-Object -First 1)[0] } else { $null }

    if ($cat -eq 'cheater') {
        Show-CheaterAnimation $pName $Summary.cheatingScore $hList $Summary.reasons $Summary.displayMessage $aiCheatFirst
    } elseif ($cat -eq 'suspect') {
        Show-SuspectAnimation $pName $Summary.cheatingScore $hList $Summary.reasons $Summary.displayMessage $aiCheatFirst
    } else {
        Show-ChadAnimation $pName $Summary.cheatingScore $Summary.displayMessage
    }
}

$script:InstActivity = @{}

function Get-GameDirOf([string]$Path) {
    if ($Path -match '^(.*)\\mods(\\|$)') { return $Matches[1] }
    return $null
}

function ConvertTo-IsoUtc($Value) {
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    return $null
}

function Format-Stamp($Value) {
    $t = ConvertTo-RunTime $Value
    if (-not $t) { return 'unknown' }
    return ('{0} ({1})' -f $t.ToLocalTime().ToString('yyyy-MM-dd HH:mm'), (Format-Ago $t))
}

function Get-InstanceActivity([string]$GameDir) {
    if (-not $GameDir) { return $null }
    $key = $GameDir.ToLower()
    if ($script:InstActivity.ContainsKey($key)) { return $script:InstActivity[$key] }
    $res = [pscustomobject]@{ LastPlayedUtc = $null; Users = @(); LogText = ''; Logs = @() }
    try {
        $logDir = Join-Path $GameDir 'logs'
        $files = @()
        if (Test-Path -LiteralPath $logDir) {
            $files = @(Get-ChildItem -LiteralPath $logDir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)\.log(\.gz)?$' } | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 12)
        }
        $latest = @($files | Where-Object { $_.Name -ieq 'latest.log' } | Select-Object -First 1)
        if ($latest.Count -gt 0) {
            $res.LastPlayedUtc = $latest[0].LastWriteTimeUtc
            $txt = Read-TextFileSafe $latest[0].FullName 20971520
            if ($txt) { $res.LogText = $txt }
        } elseif ($files.Count -gt 0) {
            $res.LastPlayedUtc = $files[0].LastWriteTimeUtc
        }
        $users = @{}
        $logList = New-Object System.Collections.Generic.List[object]
        foreach ($f in $files) {
            $txt = $null
            if ($f.Name -ieq 'latest.log') { $txt = $res.LogText } else { $txt = Read-TextFileSafe $f.FullName 8388608 }
            if (-not $txt) { continue }
            $logList.Add([pscustomobject]@{ Time = $f.LastWriteTimeUtc; Name = $f.Name; Text = [string]$txt })
            foreach ($m in [regex]::Matches($txt, 'Setting user:\s*([A-Za-z0-9_]{1,16})')) {
                $n = $m.Groups[1].Value
                if (-not $users.ContainsKey($n) -or $f.LastWriteTimeUtc -gt $users[$n]) { $users[$n] = $f.LastWriteTimeUtc }
            }
        }
        $res.Logs = @($logList | Sort-Object { $_.Time.Ticks } -Descending)
        $res.Users = @($users.Keys | ForEach-Object { [pscustomobject]@{ Name = $_; LastSeenUtc = $users[$_] } } | Sort-Object LastSeenUtc -Descending | Select-Object -First 12)
    } catch {}
    $script:InstActivity[$key] = $res
    return $res
}

function Get-ModLastUsed($Mod) {
    if (-not $Mod -or -not $Mod.LocalPath) { return $null }
    $gd = Get-GameDirOf ([string]$Mod.LocalPath)
    if (-not $gd) { return $null }
    $act = Get-InstanceActivity $gd
    if (-not $act) { return $null }
    $names = New-Object System.Collections.Generic.List[string]
    if ($Mod.ModId -and ([string]$Mod.ModId).Length -ge 4) { $names.Add([string]$Mod.ModId) }
    $stem = [IO.Path]::GetFileNameWithoutExtension(([string]$Mod.File -replace '(?i)\.(disabled|old|bak|duplicate|backup|off)$', ''))
    if ($stem.Length -ge 4) { $names.Add($stem) }
    foreach ($lg in @($act.Logs)) {
        foreach ($n in $names) {
            if ([regex]::IsMatch($lg.Text, '(?i)(?<![A-Za-z0-9_])' + [regex]::Escape($n) + '(?![A-Za-z0-9_])')) { return [pscustomobject]@{ Time = $lg.Time; Log = $lg.Name } }
        }
    }
    return $null
}

function Write-ModTimes($Mod, [string]$Indent = '      ') {
    $parts = New-Object System.Collections.Generic.List[string]
    $c = ConvertTo-RunTime $Mod.CreatedUtc
    $w = ConvertTo-RunTime $Mod.ModifiedUtc
    if ($c) { $parts.Add('added ' + (Format-Stamp $c)) }
    if ($w -and (-not $c -or [math]::Abs(($w - $c).TotalMinutes) -gt 2)) { $parts.Add('changed ' + (Format-Stamp $w)) }
    $lu = $null
    try { $lu = Get-ModLastUsed $Mod } catch {}
    $col = 'DarkGray'
    if ($lu) { $parts.Add(('last used in game {0} [{1}]' -f (Format-Stamp $lu.Time), $lu.Log)); if (((Get-Date).ToUniversalTime() - $lu.Time).TotalDays -lt 7) { $col = 'Yellow' } }
    elseif ($Mod.LocalPath) { $parts.Add('no game log shows it loaded') }
    if ($parts.Count -gt 0) { Write-Host ($Indent + 'when: ' + ($parts -join '  |  ')) -ForegroundColor $col }
}

function Test-ModLoaded($Act, $Mod) {
    if (-not $Act -or -not $Act.LogText) { return $null }
    $names = New-Object System.Collections.Generic.List[string]
    if ($Mod.ModId -and ([string]$Mod.ModId).Length -ge 4) { $names.Add([string]$Mod.ModId) }
    $stem = [IO.Path]::GetFileNameWithoutExtension(([string]$Mod.File -replace '(?i)\.(disabled|old|bak|duplicate|backup|off)$', ''))
    if ($stem.Length -ge 4) { $names.Add($stem) }
    foreach ($n in $names) {
        if ([regex]::IsMatch($Act.LogText, '(?i)(?<![A-Za-z0-9_])' + [regex]::Escape($n) + '(?![A-Za-z0-9_])')) { return $true }
    }
    return $false
}

function Get-InstanceGroups($Mods) {
    $groups = [ordered]@{}
    $newGroup = {
        param($Text)
        [pscustomobject]@{ Text = $Text; Launcher = ''; Instance = ''; Running = $false; RunInfo = $null; GameDir = $null; Activity = $null; Mods = 0; Flagged = 0; Inactive = 0
            Hacks = (New-Object System.Collections.Generic.List[string]); FlaggedMods = (New-Object System.Collections.Generic.List[object]) }
    }
    foreach ($m in $Mods) {
        if (-not $m.LocalPath) { continue }
        $folder = Split-Path -Parent $m.LocalPath
        $lab = Get-FolderLabel $folder $script:Instances
        $key = $lab.Text
        if (-not $groups.Contains($key)) {
            $g = & $newGroup $key
            if ($lab.Instance) { $g.Launcher = $lab.Instance.Launcher; $g.Instance = $lab.Instance.Instance; $g.RunInfo = $lab.Instance; $g.GameDir = $lab.Instance.GameDir }
            else { $li = Get-LauncherInfo $folder; $g.Launcher = $li.Launcher; $g.Instance = $li.Instance }
            if (-not $g.GameDir) { $g.GameDir = Get-GameDirOf $m.LocalPath }
            $groups[$key] = $g
        }
        $g = $groups[$key]
        if ($lab.Running) { $g.Running = $true }
        $g.Mods++
        if ((Get-ModClass $m) -notin 'MALWARE', 'CHEAT', 'SUSPICIOUS') { continue }
        if ([string]$m.File -match '(?i)\.(disabled|old|bak|duplicate|backup|off)$') { $g.Inactive++; continue }
        $g.Flagged++
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($h in @($m.Hacks)) {
            if ($h -and $h.Strength -ne 'weak' -and $h.Kind -ne 'Keybind') {
                [void]$names.Add([string]$h.Name)
                if (-not $g.Hacks.Contains([string]$h.Name)) { [void]$g.Hacks.Add([string]$h.Name) }
            }
        }
        [void]$g.FlaggedMods.Add([pscustomobject]@{ Mod = $m; Hacks = $names.ToArray() })
    }
    foreach ($i in @($script:Instances | Where-Object { $_ })) {
        $txt = '{0} / {1}' -f $i.Launcher, $i.Instance
        if (-not $groups.Contains($txt)) {
            $g = & $newGroup $txt
            $g.Launcher = $i.Launcher; $g.Instance = $i.Instance; $g.GameDir = $i.GameDir
            $groups[$txt] = $g
        }
        $groups[$txt].Running = $true
        $groups[$txt].RunInfo = $i
    }
    foreach ($g in $groups.Values) { $g.Activity = Get-InstanceActivity $g.GameDir }
    return @($groups.Values | Sort-Object @{ Expression = { if ($_.Running) { 0 } else { 1 } } }, @{ Expression = { -[int]$_.Flagged } }, Text)
}

function Add-TimelineEvent($List, $Time, [string]$Kind, [string]$What, [string]$Where, [string]$Source) {
    [long]$tk = 0
    if ($Time) { $tk = [long]$Time.Ticks }
    [void]$List.Add([pscustomobject]@{ Time = $Time; Ticks = $tk; Kind = $Kind; What = $What; Where = $Where; Source = $Source })
}

function Get-TimelineEvents($Groups) {
    $ev = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Groups)) {
        if (-not $g) { continue }
        foreach ($fm in @($g.FlaggedMods)) {
            try {
                $m = $fm.Mod
                $c = ConvertTo-RunTime $m.CreatedUtc
                $w = ConvertTo-RunTime $m.ModifiedUtc
                if ($c) { Add-TimelineEvent $ev $c 'downloaded' ('{0} was added to the mods folder' -f $m.File) ([string]$g.Text) 'file creation time' }
                if ($c -and $w) {
                    [double]$gap = [math]::Abs([double]($w.Ticks - $c.Ticks)) / 600000000.0
                    if ($gap -gt 2) { Add-TimelineEvent $ev $w 'modified' ('{0} was last changed' -f $m.File) ([string]$g.Text) 'file write time' }
                }
                $lp = $null
                if ($g.Activity) { $lp = ConvertTo-RunTime $g.Activity.LastPlayedUtc }
                if ($lp -and ((Test-ModLoaded $g.Activity $m) -eq $true)) { Add-TimelineEvent $ev $lp 'last used' ('{0} was loaded in the last game session' -f $m.File) ([string]$g.Text) 'latest.log' }
            } catch {}
        }
    }
    foreach ($s in @($script:Sys)) {
        try {
            if (-not $s) { continue }
            $cat = [string]$s.Category
            if ($cat -ne 'deleted' -and $cat -ne 'browser-download' -and $cat -ne 'mod-dev-deleted') { continue }
            $txt = [string]$s.Rule + ' ' + [string]$s.Detail
            if ([string]$s.Severity -eq 'low' -and $txt -notmatch '(?i)\.jar|mod') { continue }
            $kind = 'deleted'
            if ($cat -eq 'browser-download') { $kind = 'downloaded' }
            Add-TimelineEvent $ev (ConvertTo-RunTime $s.Time) $kind ([string]$s.Rule + ': ' + [string]$s.Detail) '' ([string]$s.Source)
        } catch {}
    }
    $dated = @($ev | Where-Object { $_.Time } | Sort-Object -Property Ticks -Descending)
    $undated = @($ev | Where-Object { -not $_.Time })
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($x in $dated) { [void]$all.Add($x) }
    foreach ($x in $undated) { [void]$all.Add($x) }
    return @($all | Select-Object -First 40)
}

function ConvertTo-InstanceMeta($Groups) {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Groups | Select-Object -First 12)) {
        $act = $g.Activity
        $ri = $g.RunInfo
        $users = @()
        if ($act) { $users = @($act.Users | ForEach-Object { [ordered]@{ name = $_.Name; lastSeenUtc = (ConvertTo-IsoUtc $_.LastSeenUtc) } }) }
        $fl = @($g.FlaggedMods | Select-Object -First 15 | ForEach-Object {
            $m = $_.Mod
            [ordered]@{
                file = [string]$m.File; verdict = (Limit-Text ([string]$m.Verdict) 60); hacks = @($_.Hacks | Select-Object -First 8)
                createdUtc = [string]$m.CreatedUtc; modifiedUtc = [string]$m.ModifiedUtc; loadedLastSession = (Test-ModLoaded $act $m); source = (Limit-Text ([string]$m.Source) 100)
            }
        })
        $ver = ''; $loader = ''
        if ($ri) { $ver = [string]$ri.Version; $loader = [string]$ri.Loader }
        $lp = $null
        if ($act) { $lp = ConvertTo-IsoUtc $act.LastPlayedUtc }
        [void]$out.Add([ordered]@{
            launcher = $g.Launcher; instance = $g.Instance; running = [bool]$g.Running; version = $ver; loader = $loader
            gameDir = (Hide-User ([string]$g.GameDir)); lastPlayedUtc = $lp
            modCount = $g.Mods; flaggedCount = $g.Flagged; users = $users; flagged = $fl
        })
    }
    return $out.ToArray()
}

function ConvertTo-TimelineMeta($Events) {
    return @(@($Events) | Select-Object -First 40 | ForEach-Object {
        [ordered]@{ time = (ConvertTo-IsoUtc $_.Time); kind = [string]$_.Kind; what = (Limit-Text ([string]$_.What) 200); where = (Limit-Text (Hide-User ([string]$_.Where)) 160); source = [string]$_.Source }
    })
}

function Show-InstanceSummary($Groups) {
    Write-Section 'INSTANCES'
    $running = @($script:Instances | Where-Object { $_ })
    if ($running.Count -eq 0) { Write-Host '  Currently running: nothing (Minecraft was not open during this scan)' -ForegroundColor DarkGray }
    foreach ($i in $running) {
        $ver = (('{0} {1}' -f $i.Loader, $i.Version).Trim())
        Write-Host ('  Currently running: {0} / {1}   PID {2}   account {3}   {4}' -f $i.Launcher, $i.Instance, $i.Pid, $i.Username, $ver) -ForegroundColor Green
    }
    $rows = @($Groups)
    Write-Host ('  Instances found: {0}   with hacks: {1}' -f $rows.Count, @($rows | Where-Object { $_.Flagged -gt 0 }).Count) -ForegroundColor Cyan
    if ($rows.Count -eq 0) { Write-Host '  No instances found.' -ForegroundColor DarkGray; return }
    Write-Host ''
    foreach ($g in $rows) {
        $tag = 'not running'
        $tcol = 'DarkGray'
        if ($g.Running) { $tag = 'RUNNING NOW'; $tcol = 'Green' }
        Write-Host ('  {0}   [{1}]' -f $g.Text, $tag) -ForegroundColor $tcol
        if ($g.Activity -and $g.Activity.LastPlayedUtc) { Write-Host ('      last played: {0}' -f (Format-Stamp $g.Activity.LastPlayedUtc)) -ForegroundColor Gray }
        if ($g.Flagged -gt 0) {
            $hn = ''
            if ($g.Hacks.Count -gt 0) { $hn = '  hacks: ' + ((@($g.Hacks | Select-Object -First 8)) -join ', ') }
            Write-Host ('      HAS HACKS / FLAGGED MODS: {0} of {1} mod(s){2}' -f $g.Flagged, $g.Mods, $hn) -ForegroundColor Red
            if ($g.Running) { Write-Host '      >> the hacks are in the instance that is running right now' -ForegroundColor Red }
            foreach ($fm in @($g.FlaggedMods | Select-Object -First 6)) {
                $m = $fm.Mod
                $hk = ''
                if (@($fm.Hacks).Count -gt 0) { $hk = '   hacks: ' + ((@($fm.Hacks | Select-Object -First 5)) -join ', ') }
                Write-Host ('      - {0}{1}' -f $m.File, $hk) -ForegroundColor White
                Write-Host ('          added/downloaded: {0}   last changed: {1}' -f (Format-Stamp $m.CreatedUtc), (Format-Stamp $m.ModifiedUtc)) -ForegroundColor DarkGray
                $loaded = Test-ModLoaded $g.Activity $m
                if ($loaded -eq $true) { Write-Host ('          last used: it was loaded in the last game session ({0})' -f (Format-Stamp $g.Activity.LastPlayedUtc)) -ForegroundColor Yellow }
                elseif ($loaded -eq $false) { Write-Host '          last used: not loaded in the last game session (the instance was played without it, or it is older)' -ForegroundColor DarkGray }
                else { Write-Host '          last used: no game log found for this instance' -ForegroundColor DarkGray }
            }
        } else {
            $extra = ''
            if ($g.Inactive -gt 0) { $extra = ', {0} flagged inactive copy(ies)' -f $g.Inactive }
            Write-Host ('      clean: no flagged mods ({0} checked{1})' -f $g.Mods, $extra) -ForegroundColor Green
        }
    }
}

function Show-Timeline($Groups) {
    Write-Section 'ACTIVITY TIMELINE  (flagged mods, downloads, deletions)'
    if (-not $script:IsAdmin) { Write-Host '  Run PowerShell as Administrator to include deleted-file history (Recycle Bin, NTFS journal) and Prefetch.' -ForegroundColor Yellow }
    $events = @(Get-TimelineEvents $Groups)
    if ($events.Count -eq 0) { Write-Host '  No download, deletion or usage events found for flagged mods.' -ForegroundColor DarkGray; return }
    foreach ($e in ($events | Select-Object -First 20)) {
        $when = 'time unknown     '
        if ($e.Time) { $when = $e.Time.ToLocalTime().ToString('yyyy-MM-dd HH:mm') + '  ' }
        $col = 'Gray'
        if ($e.Kind -eq 'deleted') { $col = 'Yellow' } elseif ($e.Kind -eq 'last used') { $col = 'Red' } elseif ($e.Kind -eq 'downloaded') { $col = 'Cyan' }
        Write-Host ('  {0}{1,-11} {2}' -f $when, $e.Kind, (Limit-Text (Hide-User $e.What) 110)) -ForegroundColor $col
        if ($e.Where) { Write-Host ('                        in {0}' -f $e.Where) -ForegroundColor DarkGray }
    }
}

function Show-Report($Summary, $Mods, $Jvm, $AiResults = @()) {
    $v = $Summary.verdict
    $vc = switch ($v) { 'NO FINDINGS' { 'Green' } 'MINOR NOTES' { 'Green' } 'REVIEW' { 'Yellow' } default { 'Red' } }
    Write-Section 'RESULT'
    Write-Host ''
    Write-Host ('   VERDICT: {0}      threat score {1}/100' -f $v, $Summary.threatScore) -ForegroundColor $vc
    $cn = $Summary.counts
    Write-Host ('   mods: {0} malware, {1} cheat, {2} suspicious, {3} verified, {4} unknown-clean' -f $cn.modsMalware, $cn.modsCheat, $cn.modsSuspicious, $cn.modsVerified, $cn.modsClean) -ForegroundColor Gray
    $shownReasons = if ($Summary.terminalReasons) { @($Summary.terminalReasons) } else { @($Summary.reasons) }
    foreach ($r in $shownReasons) { Write-Host ('     - ' + (Limit-Text $r 120)) -ForegroundColor $vc }
    $prevText = 'none (first scan on this PC)'
    $pt = $null
    if ($script:PrevRun) { $pt = ConvertTo-RunTime $script:PrevRun.timeUtc }
    if ($pt) { $prevText = ('{0} ({1}) - {2}' -f $pt.ToLocalTime().ToString('yyyy-MM-dd HH:mm'), (Format-Ago $pt), $script:PrevRun.verdict) }
    Write-Host ('   this scan: {0}   previous scan: {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm'), $prevText) -ForegroundColor DarkGray
    if ($script:TargetInstance) {
        $ti = $script:TargetInstance
        Write-Host ('   scanned instance: {0} / {1}  (PID {2}, account {3})' -f $ti.Launcher, $ti.Instance, $ti.Pid, $ti.Username) -ForegroundColor DarkGray
        if ($ti.GameDir) { Write-Host ('   location: ' + (Limit-Text (Hide-User $ti.GameDir) 120)) -ForegroundColor DarkGray }
    } else {
        Write-Host '   Minecraft was not running during this scan.' -ForegroundColor DarkGray
    }

    try {
        $instGroups = @(Get-InstanceGroups $Mods)
        Show-InstanceSummary $instGroups
        Show-Timeline $instGroups
    } catch { Write-Host '   (the instance and timeline sections could not be shown on this PC)' -ForegroundColor DarkGray }

    Write-Section ('MODS  ({0} jar/file(s) checked)' -f @($Mods).Count)
    $flagged = @($Mods | Where-Object { (Get-ModClass $_) -in 'MALWARE', 'CHEAT', 'SUSPICIOUS' } | Sort-Object { -[int]$_.Score })
    $flagged = @($flagged | Group-Object { '{0}|{1}' -f $_.File, $_.Sha1 } | ForEach-Object { $_.Group[0] })
    $fp = @($Mods | Where-Object { (Get-ModClass $_) -eq 'FP' })
    if ($flagged.Count -eq 0) { Write-Line '  No flagged mods.' Green }
    foreach ($m in $flagged) {
        $cls = Get-ModClass $m
        $col = if ($cls -eq 'SUSPICIOUS') { 'Yellow' } else { 'Red' }
        $nm = $m.File; if ($m.ModName) { $nm = "{0}  ({1} {2})" -f $m.File, $m.ModName, $m.ModVersion }
        Write-Host ''
        Write-Host ('  [{0}] {1}   score {2}' -f $cls, $nm, $m.Score) -ForegroundColor $col
        $srcText = 'unknown'; if ($m.Source) { $srcText = Limit-Text (Hide-User $m.Source) 70 }
        Write-Host ('      sha1 {0}   downloaded from: {1} ({2})' -f $m.Sha1, $srcText, $m.SourceTrust) -ForegroundColor DarkGray
        if ($m.LocalPath) {
            $lab = Get-FolderLabel (Split-Path -Parent $m.LocalPath) $script:Instances
            Write-Host ('      location: ' + (Limit-Text (Hide-User $m.LocalPath) 150)) -ForegroundColor DarkGray
            $labText = $lab.Text
            if ($lab.Running) { $labText += '   (RUNNING INSTANCE)' }
            Write-Host ('      instance: ' + $labText) -ForegroundColor DarkGray
        }
        Write-ModTimes $m
        $hn = @(@($m.Hacks) | Where-Object { $_ -and $_.Strength -ne 'weak' -and $_.Kind -ne 'Keybind' } | Select-Object -First 6 | ForEach-Object { $_.Name })
        if ($hn.Count -gt 0) { Write-Host ('      hacks detected: ' + ($hn -join ', ')) -ForegroundColor Red }
        foreach ($f in (@($m.Findings) | Sort-Object { -(Get-SevRank $_.Severity) } | Select-Object -First 4)) {
            Write-FindingLine $f.Severity $f.Rule (Limit-Text $f.Detail 130) '' '    '
            if ($f.Where -and ([string]$f.Where) -ne ([string]$f.Detail)) { Write-Host ('               found in: ' + (Limit-Text (Hide-User ([string]$f.Where)) 110)) -ForegroundColor DarkCyan }
        }
        $more = @($m.Findings).Count - 4
        if ($more -gt 0) { Write-Host ('      ... and {0} more finding(s) in the JSON' -f $more) -ForegroundColor DarkGray }
    }
    if ($fp.Count -gt 0) { Write-Line ('  {0} file(s) looked odd but their hash matches an official Modrinth download (probable false positive).' -f $fp.Count) DarkGray }

    $hackRows = New-Object System.Collections.Generic.List[object]
    foreach ($m in $Mods) { foreach ($h in @($m.Hacks)) { if ($h) { [void]$hackRows.Add([pscustomobject]@{ Mod = $m.File; H = $h; Cls = (Get-ModClass $m); Path = $m.LocalPath; M = $m }) } } }
    $shownRows = @($hackRows | Where-Object { $_.Cls -notin 'FP', 'VERIFIED' -and $_.H.Strength -ne 'weak' })
    Write-Section 'HACKS DETECTED  (module -> toggle key)'
    if ($shownRows.Count -eq 0) { Write-Line '  No hack modules identified.' Green }
    else {
        $lastMod = ''
        $rowsShown = 0
        foreach ($r in ($shownRows | Sort-Object Mod, { $_.H.Kind }, { $_.H.Name })) {
            if ($r.Mod -ne $lastMod) {
                if ($lastMod -and $rowsShown -gt 5) { Write-Host ('     ... and {0} more module(s) in the JSON' -f ($rowsShown - 5)) -ForegroundColor DarkGray }
                Write-Host ''; Write-Host ('  ' + $r.Mod) -ForegroundColor Cyan; $lastMod = $r.Mod; $rowsShown = 0
                if ($r.Path) { Write-Host ('     location: ' + (Limit-Text (Hide-User $r.Path) 130)) -ForegroundColor DarkGray }
                Write-ModTimes $r.M '     '
            }
            $rowsShown++
            if ($rowsShown -gt 5) { continue }
            $key = 'key: not found'; $kcol = 'DarkGray'
            if ($r.H.Keybind) { $key = 'key: ' + $r.H.Keybind; $kcol = 'Magenta' }
            Write-Host ('     {0,-26} {1,-12}' -f (Limit-Text $r.H.Name 26), $r.H.Kind) -NoNewline -ForegroundColor White
            Write-Host $key -NoNewline -ForegroundColor $kcol
            if ($r.H.KeybindSource) { Write-Host ('   [' + (Limit-Text $r.H.KeybindSource 70) + ']') -ForegroundColor DarkGray } else { Write-Host '' }
            if ($r.H.Evidence) { Write-Host ('        found in: ' + (Limit-Text (Hide-User $r.H.Evidence) 110)) -ForegroundColor DarkCyan }
        }
        if ($rowsShown -gt 5) { Write-Host ('     ... and {0} more module(s) in the JSON' -f ($rowsShown - 5)) -ForegroundColor DarkGray }
    }

    if (-not $ModsOnly) { try {
        $sysRows = New-Object System.Collections.Generic.List[object]
        foreach ($sf in @($script:Sys)) {
            try {
                if (-not $sf) { continue }
                $sv = [string]$sf.Severity
                if ($sv -ne 'high' -and $sv -ne 'medium') { continue }
                [long]$tk = 0
                $st = ConvertTo-RunTime $sf.Time
                if ($st) { $tk = [long]$st.Ticks }
                [int]$rk = 2
                if ($sv -eq 'high') { $rk = 3 }
                [void]$sysRows.Add([pscustomobject]@{ Item = $sf; Rank = $rk; Ticks = $tk })
            } catch {}
        }
        $sysShow = @($sysRows | Sort-Object -Property Rank, Ticks -Descending | Select-Object -First 25)
        Write-Section ('SYSTEM DETECTIONS  ({0} high/medium, newest first)' -f $sysRows.Count)
        if ($sysShow.Count -eq 0) { Write-Line '  Nothing high or medium on this PC.' Green }
        foreach ($row in $sysShow) {
            $f = $row.Item
            $tt = ConvertTo-RunTime $f.Time
            $when = 'time unknown'; if ($tt) { $when = Format-Stamp $tt }
            Write-Host ('  [{0,-6}] {1}' -f $f.Severity.ToUpper(), (Limit-Text $f.Rule 100)) -ForegroundColor (Get-SevColor $f.Severity)
            if ($f.Detail) { Write-Host ('           ' + (Limit-Text $f.Detail 130)) -ForegroundColor Gray }
            Write-Host ('           when: {0}   source: {1}' -f $when, (Limit-Text ([string]$f.Source) 60)) -ForegroundColor DarkGray
        }
    } catch { Write-Host '  (system detections could not be listed on this PC)' -ForegroundColor DarkGray } }

    if (@($Jvm).Count -gt 0) { Write-Section 'RUNNING GAME (JVM)' }
    foreach ($j in $Jvm) {
        Write-Host ('  PID {0} ({1}) started {2}' -f $j.Pid, $j.Name, (Format-When $j.StartedUtc)) -ForegroundColor Cyan
        $ri = @($script:Instances | Where-Object { $_ -and $_.Pid -eq $j.Pid } | Select-Object -First 1)
        if ($ri.Count -gt 0) { Write-Host ('     account {0}   {1} / {2}   {3}' -f $ri[0].Username, $ri[0].Launcher, $ri[0].Instance, (Hide-User $ri[0].GameDir)) -ForegroundColor DarkGray }
        if ($j.Memory) { Write-Host ('     memory scan: {0}   {1} MB read' -f $(if ($j.Memory.Ok) { 'completed' } else { 'not completed' }), $j.Memory.ScannedMB) -ForegroundColor DarkGray
            if ($j.Memory.Note) { Write-Host ('     note: ' + $j.Memory.Note) -ForegroundColor DarkGray } }
        if (@($j.Findings).Count -eq 0) { Write-Line '     no suspicious launch flags, DLLs or memory strings.' Green }
        foreach ($f in @($j.Findings)) { Write-FindingLine $f.Severity $f.Rule (Limit-Text $f.Detail 130) '' '    ' }
    }

    if ($AiResults -and @($AiResults).Count -gt 0) {
        $aiShown = @($AiResults | Where-Object { $_.verdict -ne 'CHAD' })
        $aiClean = @($AiResults).Count - $aiShown.Count
        Write-Section 'CACTUS AI MOD INSPECTION'
        if ($aiShown.Count -eq 0) { Write-Line '  Nothing flagged by the AI.' Green }
        foreach ($ai in $aiShown) {
            $col = switch ($ai.verdict) { 'CHEAT' { 'Red' } 'SUSPECT' { 'Yellow' } default { 'Green' } }
            Write-Host ('  [{0}] {1}  ({2}% score)' -f $ai.verdict, $ai.file, $ai.cheating_score) -ForegroundColor $col
            if ($ai.troll_summary) { Write-Host ('      AI Note: ' + $ai.troll_summary) -ForegroundColor Gray }
            if ($ai.explanation) { Write-Host ('      Details: ' + $ai.explanation) -ForegroundColor DarkGray }
        }
        if ($aiClean -gt 0) { Write-Line ('  {0} other mod(s) judged clean by the AI.' -f $aiClean) DarkGray }
    }

    if ($script:Native -and -not $script:ProfilerOk) { Write-Host ('  NOTE: the deep code profiler could not be compiled here; the AI inspection had less evidence. ({0})' -f (Limit-Text $script:ProfilerError 120)) -ForegroundColor Yellow }
    if (-not $script:Native) { Write-Host ('  NOTE: the class-file analyser could not be compiled here; jar checks ran in text-only mode. ({0})' -f (Limit-Text $script:NativeError 120)) -ForegroundColor Yellow }
}

function ConvertTo-HackObj($h) {
    [ordered]@{ name = $h.Name; kind = $h.Kind; category = $h.Category; strength = $h.Strength; evidence = $h.Evidence; keybind = $h.Keybind; keybindSource = $h.KeybindSource }
}
function ConvertTo-FindingObj($f) {
    [ordered]@{ severity = $f.Severity; category = $f.Category; rule = $f.Rule; detail = $f.Detail; 'where' = $f.Where }
}

function New-ReportObject($Summary, $Mods, $Jvm, $Meta, [int]$Level = 0) {
    $modOut = New-Object System.Collections.Generic.List[object]
    $profSent = 0
    foreach ($m in $Mods) {
        $cls = Get-ModClass $m
        if ($Level -ge 1 -and $cls -in 'CLEAN', 'VERIFIED') { continue }
        $fcap = 200; if ($Level -ge 2) { $fcap = 12 }
        $item = [ordered]@{
            file = $m.File; folder = $m.Folder; sizeKb = $m.SizeKB; sha1 = $m.Sha1; sha256 = $m.Sha256
            modId = $m.ModId; modName = $m.ModName; modVersion = $m.ModVersion; loader = $m.Loader; modrinth = $m.Modrinth
            source = $m.Source; sourceTrust = $m.SourceTrust; modifiedUtc = $m.ModifiedUtc
            classes = $m.Classes; nestedJars = $m.NestedJars; deepScanned = $m.DeepScanned
            score = $m.Score; verdict = $m.Verdict; 'class' = $cls
            hacks = @(@($m.Hacks) | Where-Object { $_ } | ForEach-Object { ConvertTo-HackObj $_ })
            findings = @(@($m.Findings) | Sort-Object { -(Get-SevRank $_.Severity) } | Select-Object -First $fcap | ForEach-Object { ConvertTo-FindingObj $_ })
        }
        if ($Level -eq 0 -and $m.Profile -and $profSent -lt 40) { $item['profile'] = $m.Profile; $profSent++ }
        [void]$modOut.Add($item)
    }
    $sys = $script:Sys.ToArray()
    if ($Level -ge 1) { $sys = @($sys | Where-Object { $_.Severity -ne 'low' }) }
    if ($Level -ge 2) { $sys = @($sys | Select-Object -First 150) }
    $sysOut = @($sys | ForEach-Object { [ordered]@{ severity = $_.Severity; category = $_.Category; rule = $_.Rule; detail = $_.Detail; time = $_.Time; source = $_.Source } })
    $jvmOut = @($Jvm | ForEach-Object {
        $mem = $null
        if ($_.Memory) { $mem = [ordered]@{ ok = $_.Memory.Ok; note = $_.Memory.Note; scannedMb = $_.Memory.ScannedMB; clientHits = @(@($_.Memory.ClientHits) | ForEach-Object { [ordered]@{ term = $_.Term; count = $_.Count } }); moduleHits = @(@($_.Memory.ModuleHits) | ForEach-Object { [ordered]@{ term = $_.Term; count = $_.Count } }) } }
        [ordered]@{ 'pid' = $_.Pid; name = $_.Name; startedUtc = $_.StartedUtc; findings = @(@($_.Findings) | ForEach-Object { ConvertTo-FindingObj $_ }); memory = $mem }
    })
    $kbOut = @($script:Keybinds | ForEach-Object { [ordered]@{ name = $_.Name; key = $_.Key; source = $_.Source; confidence = $_.Confidence; matchedMod = [bool]$_.Used } })
    $modsStat = @($script:ModStatus | ForEach-Object { [ordered]@{ name = $_.Name; status = $_.Status; note = $_.Note; findings = $_.Findings } })
    [ordered]@{
        schema = 2
        scriptVersion = $ScriptVersion
        generatedUtc = $script:NowUtc.ToString('o')
        lookbackHours = [math]::Max(1, $LookbackHours)
        trimLevel = $Level
        meta = $Meta
        summary = $Summary
        category = $Summary.category
        cheatingScore = $Summary.cheatingScore
        displayMessage = $Summary.displayMessage
        aiResults = $Summary.aiResults
        mods = $modOut.ToArray()
        jvm = $jvmOut
        system = $sysOut
        keybinds = $kbOut
        modules = $modsStat
    }
}

function ConvertTo-JsonText($Obj) { return ($Obj | ConvertTo-Json -Depth 10) }

function Save-ReportFile($Json) {
    try { if (-not (Test-Path -LiteralPath $OutDir)) { [void](New-Item -ItemType Directory -Path $OutDir -Force) } } catch {}
    $name = 'CactusHacksDetector-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
    $path = Join-Path $OutDir $name
    try { [IO.File]::WriteAllText($path, $Json, (New-Object Text.UTF8Encoding($false))); return $path } catch { return $null }
}

function Send-Report($Summary, $Mods, $Jvm, $Meta) {
    if (-not (Test-ApiBase $ApiBase) -or $ApiBase -match 'CHANGE-ME') { Write-Line '  This copy of the script has no database address set (edit $ApiBase or use -Api). Nothing was uploaded.' Red; return $null }

    $uploadMeta = [ordered]@{}
    foreach ($property in $Meta.GetEnumerator()) { $uploadMeta[$property.Key] = $property.Value }
    $bytes = $null
    for ($lv = 0; $lv -le 2; $lv++) {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-JsonText (New-ReportObject $Summary $Mods $Jvm $uploadMeta $lv)))
        if ($bytes.Length -le 900000) { break }
    }
    if ($bytes.Length -gt 900000) { Write-Line '  The report is too large to upload even after trimming. Send the JSON file to staff instead.' Red; return $null }

    try {
        $resp = Invoke-RestMethod -Method Post -Uri ($ApiBase + '/upload') -Headers @{ 'X-Scan-Consent' = 'yes'; 'X-Scan-Client' = ('Scan.ps1/' + $ScriptVersion) } -ContentType 'application/json; charset=utf-8' -Body $bytes -TimeoutSec 60 -ErrorAction Stop
        $id = ''; if ($resp -and $resp.id) { $id = [string]$resp.id }
        $token = ''; if ($resp -and $resp.uploadToken) { $token = [string]$resp.uploadToken }
        return [pscustomobject]@{ Ok = $true; Id = $id; Token = $token; Duplicate = [bool]($resp -and $resp.duplicate) }
    } catch {
        $code = 0
        try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        $why = switch ($code) {
            400 { 'The server rejected the report format.' }
            409 { 'This exact report could not be linked to a stored scan.' }
            413 { 'The report was too large for the server.' }
            415 { 'The server did not accept the upload type.' }
            429 { 'Too many uploads from this connection. Wait and try again.' }
            default { 'Could not reach the server ({0}).' -f $(if ($code) { "HTTP $code" } else { 'no response' }) }
        }
        Write-Line ('  Report upload failed: ' + $why) Red
        Write-Line '  The JSON file is still saved on this PC.' Yellow
        return $null
    }
}

function Get-ModUploadCandidates($Mods) {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in $Mods) {
        $cls = Get-ModClass $m
        $isFlagged = $cls -in 'MALWARE', 'CHEAT', 'SUSPICIOUS'
        $isUnknownRelevant = ($cls -eq 'CLEAN' -and -not $m.Modrinth -and [int]$m.Score -gt 0)
        $isUnverified = (-not $m.Modrinth -and $cls -notin 'FP', 'VERIFIED')
        if (-not ($isFlagged -or $isUnknownRelevant -or $isUnverified)) { continue }
        if (-not $m.LocalPath) { continue }
        try { $fi = Get-Item -LiteralPath $m.LocalPath -ErrorAction Stop } catch { continue }
        if ($fi.Length -le 0 -or $fi.Length -gt ($MaxModUploadMB * 1MB)) { continue }
        [void]$out.Add([pscustomobject]@{ Mod = $m; Path = $fi.FullName; Size = [long]$fi.Length; Class = $cls })
    }
    return @($out | Sort-Object @{ Expression = { if ($_.Class -in 'MALWARE', 'CHEAT', 'SUSPICIOUS') { 0 } else { 1 } } }, @{ Expression = { -[int]$_.Mod.Score } })
}

function Send-ModFiles([string]$ScanId, [string]$Token, $Mods) {
    if (-not $ScanId -or -not $Token) {
        Write-Line '  Mod binaries were not uploaded (server did not issue an upload token; set UPLOAD_TOKEN_SECRET).' DarkYellow
        return
    }
    $candidates = @(Get-ModUploadCandidates $Mods)
    if ($candidates.Count -eq 0) { return }

    $headers = @{ 'X-Scan-Consent' = 'yes'; 'X-Scan-Client' = ('Scan.ps1/' + $ScriptVersion) }
    $sent = 0; $sentBytes = [long]0
    $seenSha = @{}
    foreach ($c in $candidates) {
        if ($sent -ge $MaxModUploadsPerScan) { break }
        if (($sentBytes + $c.Size) -gt $MaxModUploadBytes) { continue }
        $sha256 = [string]$c.Mod.Sha256
        if (-not $sha256) { $sha256 = Get-FileHashSafe $c.Path 'SHA256' }
        $sha1 = [string]$c.Mod.Sha1
        if (-not $sha256) { continue }

        if ($seenSha.ContainsKey($sha256)) { continue }
        $seenSha[$sha256] = $true
        try {
            $signBody = @{ scanId = $ScanId; token = $Token; fileName = [string]$c.Mod.File; sizeBytes = $c.Size; sha256 = $sha256; sha1 = $sha1 } | ConvertTo-Json -Compress
            $slot = Invoke-RestMethod -Method Post -Uri ($ApiBase + '/mods/sign') -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $signBody -TimeoutSec 60 -ErrorAction Stop
            if (-not $slot.uploadUrl -or -not $slot.fileId) { throw 'The server did not return an upload URL.' }

            [void](Invoke-WebRequest -Method Put -Uri ([string]$slot.uploadUrl) -InFile $c.Path -ContentType 'application/java-archive' -Headers @{ 'x-upsert' = 'false' } -TimeoutSec 300 -UseBasicParsing -ErrorAction Stop)

            $completeBody = @{ scanId = $ScanId; token = $Token; fileId = [string]$slot.fileId } | ConvertTo-Json -Compress
            $done = $false
            for ($try = 1; $try -le 3; $try++) {
                try {
                    [void](Invoke-RestMethod -Method Post -Uri ($ApiBase + '/mods/complete') -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $completeBody -TimeoutSec 60 -ErrorAction Stop)
                    $done = $true; break
                } catch {
                    if ($try -lt 3) { Start-Sleep -Seconds 2 } else { throw }
                }
            }
            if (-not $done) { throw 'The server could not confirm the upload.' }
            $sent++; $sentBytes += $c.Size
            Start-Sleep -Milliseconds 500
        } catch {
            $code = 0
            try { $code = [int]$_.Exception.Response.StatusCode } catch {}
            $why = switch ($code) {
                403 { 'not flagged in the stored report / upload token rejected' }
                409 { 'already uploaded or file limit reached' }
                413 { 'larger than the server accepts' }
                429 { 'rate limited' }
                default { $_.Exception.Message }
            }
            Write-Line ('  Could not upload {0}: {1}' -f $c.Mod.File, (Limit-Text $why 160)) Yellow
            if ($code -eq 429) { Write-Line '  Upload limit reached - the remaining mod files were not uploaded.' DarkYellow; break }
        }
    }
}

function Get-Sha256Hex([string]$Text) {
    $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
    return (($h | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-ZipMagic([string]$Path) {
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite, Delete')
        try { $b = New-Object byte[] 4; $n = $fs.Read($b, 0, 4); return ($n -eq 4 -and $b[0] -eq 0x50 -and $b[1] -eq 0x4B -and $b[2] -eq 3 -and $b[3] -eq 4) } finally { $fs.Dispose() }
    } catch { return $false }
}

function Read-BadHashFile([string]$Path) {
    $script:BadHashes = @{}
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path)) { Write-Line ("  -BadHashFile not found: {0}" -f $Path) Yellow; return }
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        if ($line -match '^\s*([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b\s*[#;,]?\s*(.*)$') {
            $label = $Matches[2].Trim(); if (-not $label) { $label = 'known-bad hash list' }
            $script:BadHashes[$Matches[1].ToLower()] = (Limit-Text $label 80)
        }
    }
    Write-Line ("  loaded {0} known-bad hash(es)" -f $script:BadHashes.Count) DarkGray
}

function Invoke-Main {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Write-Host ''
    Write-Host '  CactusHacksDetector v1 - Minecraft cheat / malware / activity scan' -ForegroundColor Cyan
    Write-Host '  Deep mod inspection.' -ForegroundColor Gray
    if (-not $script:IsAdmin -and -not $ModsOnly) { Write-Host '  Tip: Run as Administrator for deep forensic checks (Prefetch, BAM, Security log).' -ForegroundColor Yellow }
    Read-BadHashFile $BadHashFile

    $script:PrevRun = Read-LastRun
    Write-Host ''
    Show-LastRun $script:PrevRun
    $script:Instances = @(Get-RunningInstances)
    $sel = Select-MinecraftAccount $Username $script:Instances
    if (-not $sel) {
        Write-Host ''
        Write-Host '  Scan stopped: the username could not be verified. Run the scan again with the username you really play on.' -ForegroundColor Red
        return
    }
    $script:RunSw.Restart()
    $script:SelectedAccount = $sel.Account
    $script:TargetInstance = $sel.Instance
    Show-ScanTarget $script:Instances $sel
    $script:Accounts = Get-MinecraftAccountReport $script:SelectedAccount

    foreach ($p in @(Get-McJavaProcesses)) {
        try { $s = $p.CreationDate.ToUniversalTime(); if (-not $script:JvmStartUtc -or $s -lt $script:JvmStartUtc) { $script:JvmStartUtc = $s } } catch {}
    }

    Write-Host '  PHASE 1/3 -- quick mod and file scan' -ForegroundColor Cyan
    Write-Section 'MOD SCAN'
    $folders = @(Find-ModFolders)
    if ($folders.Count -eq 0) { Write-Line '  No Minecraft mods folders found. Use -ModPath <folder> to point at one.' Yellow }
    foreach ($f in $folders) {
        $lab = Get-FolderLabel $f $script:Instances
        $line = '  folder: ' + (Hide-User $f) + '   [' + $lab.Text + ']'
        if ($lab.Running) { Write-Line ($line + '   <-- RUNNING INSTANCE') Green } else { Write-Line $line DarkGray }
    }
    foreach ($f in $folders) {
        try {
            $fd = Get-Item -LiteralPath $f -Force -ErrorAction Stop
            if ($fd.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $tg = ''; try { $tg = (@($fd.Target) -join ', ') } catch {}
                Add-Sys 'medium' 'bypass' 'Mods folder is a junction or symbolic link (it may point somewhere else)' ((Hide-User $f) + ' -> ' + (Hide-User $tg)) $fd.LastWriteTimeUtc 'mods folder'
            }
            if (($fd.Attributes -band [IO.FileAttributes]::Hidden) -or ($fd.Attributes -band [IO.FileAttributes]::System)) {
                Add-Sys 'medium' 'bypass' 'Mods folder is hidden with the Hidden/System attribute' (Hide-User $f) $fd.LastWriteTimeUtc 'mods folder'
            }
        } catch {}
    }

    $jarExt = '.jar', '.disabled', '.old', '.bak'
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($f in $folders) {
        foreach ($fi in @(Get-ChildItem -LiteralPath $f -File -Force -Recurse -Depth 3 -ErrorAction SilentlyContinue)) { [void]$items.Add($fi) }
    }
    $seen = @{}
    $uniq = New-Object System.Collections.Generic.List[object]
    foreach ($fi in $items) { if (-not $seen.ContainsKey($fi.FullName.ToLower())) { $seen[$fi.FullName.ToLower()] = $true; [void]$uniq.Add($fi) } }
    $jars = @($uniq | Where-Object { $_.Extension.ToLower() -in $jarExt -or $_.Name -match '(?i)\.jar\.' } | Select-Object -First 1500)
    $jarSet = @{}; foreach ($j in $jars) { $jarSet[$j.FullName] = $true }
    $others = @($uniq | Where-Object { -not $jarSet.ContainsKey($_.FullName) -and $_.Length -gt 0 })
    $strayMap = @{}
    if (-not $ModsOnly) {
        $script:StrayJars = @()
        Invoke-Module 'Mod jars outside the mods folders' { $script:StrayJars = @(Find-StrayModJars $jarSet) }
        foreach ($sj in @($script:StrayJars)) {
            if (-not $jarSet.ContainsKey($sj.FullName)) { $jars += $sj; $jarSet[$sj.FullName] = $true; $strayMap[$sj.FullName] = $true }
        }
        if ($strayMap.Count -gt 0) { Write-Line ('  {0} mod jar(s) found outside the mods folders (Downloads, Desktop, Temp, game folder)' -f $strayMap.Count) Yellow }
    }
    Write-Line ('  {0} jar file(s), {1} other file(s)' -f $jars.Count, $others.Count) Gray

    $hashes = @{}
    $sha1Map = @{}
    foreach ($j in $jars) { $h = Get-FileHashes $j.FullName; $hashes[$j.FullName] = $h; if ($h -and $h.Sha1) { $sha1Map[$h.Sha1] = $j.FullName } }
    $modrinth = @{}
    if (-not $NoOnline -and $sha1Map.Count -gt 0) {
        Write-Line '  checking hashes against Modrinth...' DarkGray
        $mr = Get-ModrinthMatches $sha1Map
        if ($mr) { $modrinth = $mr }
        if ($modrinth.Count -gt 0) { Write-Line ('  {0} jar(s) verified as official Modrinth downloads' -f $modrinth.Count) DarkGray }
    } elseif ($NoOnline) { Write-Line '  online hash check skipped (-NoOnline)' DarkGray }

    Read-VerifiedCache
    $script:VerifiedOver = $false; $script:VerifiedSpent = 0.0
    $jars = @($jars | Sort-Object @{ Expression = { if ($hashes[$_.FullName] -and $hashes[$_.FullName].Sha1 -and $modrinth.ContainsKey($hashes[$_.FullName].Sha1)) { 1 } else { 0 } } }, Length)
    $unvLeft = 0.0; $verLeft = 0.0
    foreach ($j in $jars) {
        if ($hashes[$j.FullName] -and $hashes[$j.FullName].Sha1 -and $modrinth.ContainsKey($hashes[$j.FullName].Sha1)) { $verLeft += [double]$j.Length } else { $unvLeft += [double]$j.Length }
    }
    $scanSw = [Diagnostics.Stopwatch]::StartNew()
    $doneBytes = 0.0; $budgetSkipped = 0; $cacheSkipped = 0
    $mods = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($j in $jars) {
        $i++
        $el = $scanSw.Elapsed
        $eta = ''
        if ($doneBytes -gt 0 -and $el.TotalSeconds -gt 2) {
            $remain = $unvLeft; if (-not $script:VerifiedOver) { $remain += $verLeft }
            $eta = 'ETA ~' + (Format-Span ([TimeSpan]::FromSeconds($el.TotalSeconds * ($remain / $doneBytes))))
        }
        Write-Host ("`r  scanning {0}/{1}  elapsed {2}  {3}  {4}" -f $i, $jars.Count, (Format-Span $el), $eta.PadRight(11), (Limit-Text $j.Name 32).PadRight(32)) -NoNewline -ForegroundColor DarkGray
        $isVer = [bool]($hashes[$j.FullName] -and $hashes[$j.FullName].Sha1 -and $modrinth.ContainsKey($hashes[$j.FullName].Sha1))
        $t0 = $scanSw.Elapsed.TotalSeconds
        try {
            $r = Invoke-JarScan $j $hashes[$j.FullName] $modrinth
            $dt = $scanSw.Elapsed.TotalSeconds - $t0
            if ($isVer) { $verLeft -= [double]$j.Length } else { $unvLeft -= [double]$j.Length }
            if ($r -and $r.DeepScanned) {
                $doneBytes += [double]$j.Length
                if ($isVer) {
                    $script:VerifiedSpent += $dt
                    if ($r.Verdict -like 'VERIFIED*' -and @($r.Findings | Where-Object { $_.Severity -in 'high', 'medium' }).Count -eq 0 -and @($r.Hacks).Count -eq 0 -and $r.Sha1) { $script:VerifiedCache[[string]$r.Sha1] = $true }
                    if ($VerifiedSeconds -gt 0 -and $script:VerifiedSpent -gt $VerifiedSeconds -and -not $script:VerifiedOver) { $script:VerifiedOver = $true }
                }
            } elseif ($r -and $isVer) {
                if ($script:LastSkipWhy -eq 'budget') { $budgetSkipped++ } elseif ($script:LastSkipWhy -eq 'cache') { $cacheSkipped++ }
            }
            if ($r -and $strayMap.ContainsKey($j.FullName)) {
                $r.Findings = @($r.Findings) + [pscustomobject]@{ Severity = 'low'; Category = 'location'; Rule = 'Mod jar found outside the mods folders (loaded another way, or left behind)'; Detail = (Hide-User $j.DirectoryName); Where = $j.Name }
            }
            if ($r) { [void]$mods.Add($r) }
        } catch {
            [void]$mods.Add([pscustomobject]@{ File = $j.Name; LocalPath = $j.FullName; Folder = (Hide-User $j.DirectoryName); SizeKB = [math]::Round($j.Length / 1KB); Sha1 = $null; Sha256 = $null; ModId = $null; ModName = $null; ModVersion = $null; Loader = $null; Modrinth = $null; Source = $null; SourceTrust = 'unknown'; ModifiedUtc = $j.LastWriteTimeUtc.ToString('o'); Classes = 0; NestedJars = 0; DeepScanned = $false; Score = 0; Verdict = 'UNKNOWN'; Hacks = @(); Findings = @([pscustomobject]@{ Severity = 'low'; Category = 'scan-error'; Rule = 'Could not scan this file'; Detail = (Limit-Text $_.Exception.Message 120); Where = $j.Name }) })
        }
    }
    if ($jars.Count -gt 0) { Write-Host ''; }
    Write-VerifiedCache
    if ($cacheSkipped -gt 0) { Write-Line ('  {0} verified mod(s) were checked clean in an earlier scan and skipped (same file, same detection rules)' -f $cacheSkipped) DarkGray }
    if ($budgetSkipped -gt 0) { Write-Line ('  {0} verified mod(s) were not deep-scanned (time limit {1}s). Run the scan again to continue, or use -VerifiedSeconds 0 for all at once.' -f $budgetSkipped, $VerifiedSeconds) Yellow }

    $script:AiJob = $null

    foreach ($o in $others) {
        if (($o.Attributes -band [IO.FileAttributes]::Hidden) -and $o.Name -notmatch '(?i)^(desktop\.ini|thumbs\.db|\.ds_store)$') {
            Add-Sys 'medium' 'bypass' 'Hidden file inside a mods folder' (Hide-User $o.FullName) $o.LastWriteTimeUtc 'mods folder'
        }
    }
    foreach ($o in $others) {
        $isZip = $false
        if ($o.Length -ge 1024 -and $o.Length -le 200MB -and $o.Extension.ToLower() -notin '.zip', '.json', '.toml', '.cfg', '.properties', '.txt', '.md', '.log', '.png', '.jpg', '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.lnk') { $isZip = Test-ZipMagic $o.FullName }
        if ($isZip) {
            $h = Get-FileHashes $o.FullName
            $r = Invoke-JarScan $o $h $modrinth
            if ($r) {
                $isDisabled = ($o.Extension -in '.disabled', '.old', '.bak', '.duplicate', '.backup', '.off', '.orig', '.prev') -or ($o.Name -match '(?i)\.jar\.[a-z0-9_-]{1,12}$')
                $isVer = [bool]($h -and $h.Sha1 -and $modrinth.ContainsKey($h.Sha1))
                if (-not $isDisabled -and -not $isVer) {
                    $r.Findings = @($r.Findings) + [pscustomobject]@{ Severity = 'high'; Category = 'bypass'; Rule = 'A jar is disguised with a different file extension'; Detail = $o.Name; Where = $o.Name }
                    $r.Score = [math]::Min(100, [int]$r.Score + 25)
                    if ($r.Verdict -notlike 'MALWARE*') { $r.Verdict = 'CHEAT' }
                }
                [void]$mods.Add($r)
            }
        } else {
            $h = Get-FileHashes $o.FullName
            $r = Invoke-LooseFileScan $o $h
            if ($r) { [void]$mods.Add($r) }
        }
    }

    Write-Host '  PHASE 2/3 -- game files, keybinds, logs and running Minecraft' -ForegroundColor Cyan
    $gameDirs = New-Object System.Collections.Generic.List[string]
    foreach ($f in $folders) { $pd = Split-Path -Parent $f; if ($pd -and -not $gameDirs.Contains($pd)) { $gameDirs.Add($pd) } }
    if ($env:APPDATA) { $dm = Join-Path $env:APPDATA '.minecraft'; if ((Test-Path -LiteralPath $dm) -and -not $gameDirs.Contains($dm)) { $gameDirs.Add($dm) } }
    $known = @{}
    foreach ($m in $mods) { if ($m.ModId) { $known[([string]$m.ModId).ToLower()] = $true } }
    Invoke-Module 'Game folders (options, logs, client traces)' {
        foreach ($gd in $gameDirs) {
            Read-OptionsKeybinds $gd
            Find-ClientTraces $gd
            Scan-GameLogs $gd $known
        }
    }
    Join-Keybinds $mods

    Write-Section 'SYSTEM FORENSICS'
    $jvm = @()
    Invoke-Module 'Running game (JVM, DLLs, memory)' { $script:JvmResult = @(Get-JvmReport) }
    if ($script:JvmResult) { $jvm = @($script:JvmResult) }

    if (-not $ModsOnly) { Write-Host '  PHASE 3/3 -- deep system forensics' -ForegroundColor Cyan }
    if ($ModsOnly) { Write-Line '  -ModsOnly: system forensics skipped.' DarkYellow }
    else {
        Invoke-Module 'Processes and tools'               { Invoke-ProcessChecks }
        Invoke-Module 'Shell history (PowerShell, cmd)'   { Invoke-HistoryChecks }
        Invoke-Module 'Browser downloads & history (Chrome)' { Invoke-BrowserChecks }
        Invoke-Module 'Custom mod development & deletion'    { Invoke-ModDevDeletionsCheck }
        Invoke-Module 'Event logs (cleared, clock, AV)'   { Invoke-EventLogChecks } -NeedsAdmin
        Invoke-Module 'Prefetch / BAM / UserAssist / Shim' { Read-PrefetchTraces; Read-BamTraces; Read-UserAssistTraces; Read-ShimCacheTraces; Test-ExecRows } -NeedsAdmin
        Invoke-Module 'Recycle Bin (deleted files)'       { Invoke-RecycleBinChecks }
        Invoke-Module 'NTFS change journal (USN)'         { Invoke-UsnChecks } -NeedsAdmin
        Invoke-Module 'Recent files and shortcuts'        { Invoke-RecentFileChecks }
        Invoke-Module 'USB / keyboard / mouse changes'    { Invoke-DeviceChecks }
        Invoke-Module 'Network and remote access'         { Invoke-NetworkChecks }
        Invoke-Module 'DNS cache'                         { Invoke-DnsChecks }
        Invoke-Module 'Startup, tasks, services'          { Invoke-StartupChecks }
        Invoke-Module 'Drivers and boot configuration'    { Invoke-DriverChecks } -NeedsAdmin
        Invoke-Module 'Named pipes'                       { Invoke-PipeChecks }
        Invoke-Module 'Installed software'                { Invoke-InstalledSoftwareChecks }
    }

    $modsArr = $mods.ToArray()

    $summary = Get-Summary $modsArr $jvm @()
    $os = $null; $boot = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $boot = $os.LastBootUpTime.ToUniversalTime().ToString('o') } catch {}
    $guid = ''; try { $guid = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid } catch {}
    $pcId = $null; if ($guid) { $pcId = (Get-Sha256Hex ('CactusHacksDetector:' + $guid)).Substring(0, 16) }
    $osName = $null; $osBuild = $null; if ($os) { $osName = [string]$os.Caption; $osBuild = [string]$os.BuildNumber }
    $accounts = if ($script:Accounts) { $script:Accounts } else { Get-MinecraftAccountProfiles }
    $instMeta = @(); $tlMeta = @()
    try {
        $instGroupsMeta = @(Get-InstanceGroups $modsArr)
        $instMeta = @(ConvertTo-InstanceMeta $instGroupsMeta)
        $tlMeta = @(ConvertTo-TimelineMeta (Get-TimelineEvents $instGroupsMeta))
    } catch { $instMeta = @(); $tlMeta = @() }
    $tgt = $null
    if ($script:TargetInstance) {
        $ti = $script:TargetInstance
        $tgt = [ordered]@{ pid = $ti.Pid; launcher = $ti.Launcher; instance = $ti.Instance; version = $ti.Version; loader = $ti.Loader; gameDir = (Hide-User $ti.GameDir) }
    }
    $prevUtc = $null
    if ($script:PrevRun -and $script:PrevRun.timeUtc) { $pt0 = ConvertTo-RunTime $script:PrevRun.timeUtc; if ($pt0) { $prevUtc = $pt0.ToString('o') } }
    $meta = [ordered]@{
        pcId = $pcId; os = $osName; osBuild = $osBuild; psVersion = $PSVersionTable.PSVersion.ToString()
        admin = $script:IsAdmin; native = $script:Native; nativeError = (Limit-Text $script:NativeError 160)
        scriptSha256 = $script:ScriptSha; online = (-not $NoOnline); modsOnly = [bool]$ModsOnly
        modFolders = $folders.Count; jarCount = $jars.Count; bootUtc = $boot; gameRunning = (@($jvm).Count -gt 0)
        minecraftAccounts = $accounts
        scanTarget = $tgt
        instances = $instMeta
        timeline = $tlMeta
        deepTimeline = ($script:IsAdmin -and -not $ModsOnly)
        usernameCheck = $script:UsernameCheck
        previousScanUtc = $prevUtc
        durationSec = [math]::Round($sw.Elapsed.TotalSeconds)
    }

    $script:Accounts = $accounts

    $flagged = ($summary.verdict -notin 'NO FINDINGS', 'MINOR NOTES')
    Write-Host ''
    if ($JsonOnlyIfFlagged -and -not $flagged) {
        Write-Line '  Nothing flagged - JSON file not written (-JsonOnlyIfFlagged).' DarkGray
    } else {
        $json = ConvertTo-JsonText (New-ReportObject $summary $modsArr $jvm $meta 0)
        $path = Save-ReportFile $json
        if ($path) { Write-Line ('  JSON saved: ' + $path) Green } else { Write-Line '  Could not write the JSON file (check -OutDir).' Red }
    }

    $aiResults = @()
    $upload = Send-Report $summary $modsArr $jvm $meta
    if ($upload) {
        Send-ModFiles $upload.Id $upload.Token $modsArr
        if ($upload.Id -and -not $NoOnline) {
            Write-Host ''
            Write-Host '  ==========================================================================' -ForegroundColor Cyan
            Write-Host '  Scan done, waiting for Cactus AI for the result...' -ForegroundColor Yellow
            Write-Host '  ==========================================================================' -ForegroundColor Cyan
            $pollUrl = $ApiBase + '/scan/' + $upload.Id + '/status'

            $pollStart = Get-Date
            $maxWaitSec = 900
            $failStreak = 0
            $lastShown = ''
            $aiFinished = $false
            while (((Get-Date) - $pollStart).TotalSeconds -lt $maxWaitSec) {
                Start-Sleep -Seconds 2
                try {
                    $st = Invoke-RestMethod -Method Get -Uri $pollUrl -TimeoutSec 10 -ErrorAction Stop
                    $failStreak = 0
                } catch {
                    $failStreak++
                    if ($failStreak -ge 5) { break }
                    continue
                }
                if (-not $st) { continue }
                if ($st.aiStatus -eq 'completed') {
                    if ($st.aiResults -and @($st.aiResults).Count -gt 0) {
                        $aiResults = @($st.aiResults)
                        Apply-AiResultsToMods $modsArr $aiResults
                        $summary = Get-Summary $modsArr $jvm $aiResults
                        Write-Host '  Cactus AI inspection complete!' -ForegroundColor Green
                    }
                    $aiFinished = $true
                    break
                }
                if ($st.aiStatus -eq 'none') { $aiFinished = $true; break }
                $pos = 0
                if ($st.queuePosition) { $pos = [int]$st.queuePosition }
                if ($pos -gt 1) {
                    $shown = ('  Queue position: {0}' -f $pos)
                    if ($st.queueTotal) { $shown += (' (of {0} waiting)' -f [int]$st.queueTotal) }
                } elseif ($pos -eq 1) {
                    $shown = '  Queue position: 1 - Cactus AI is inspecting your mods now...'
                } else {
                    $shown = '  Waiting for Cactus AI...'
                }
                if ($shown -ne $lastShown) { Write-Host $shown -ForegroundColor Yellow; $lastShown = $shown }
            }
            if (-not $aiFinished) {
                Write-Host '  Cactus AI is taking longer than expected. Showing the local results; the AI verdict will be added to your scan for staff.' -ForegroundColor DarkYellow
            }
        }
    }

    Write-LastRun $summary $script:SelectedAccount.Name
    Show-Report $summary $modsArr $jvm $aiResults
    Write-Host ''
    Write-Host ('  Done in {0} (mm:ss).' -f (Format-Span $sw.Elapsed)) -ForegroundColor DarkGray
    Write-Host '  This is evidence for a human to review, not proof. Check flagged items before acting on them.' -ForegroundColor DarkGray
    Show-Verdict $summary $modsArr $aiResults
}

$script:ScriptSha = $null
try {
    if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) { $script:ScriptSha = Get-FileHashSafe $PSCommandPath 'SHA256' }
    elseif ($MyInvocation.MyCommand.ScriptBlock) { $script:ScriptSha = Get-Sha256Hex ($MyInvocation.MyCommand.ScriptBlock.ToString()) }
} catch {}

try { Invoke-Main }
catch {
    Write-Host ('  CactusHacksDetector stopped because of an unexpected error: ' + (Limit-Text (Hide-User $_.Exception.Message) 200)) -ForegroundColor Red
    try { Write-Host ('  (script line ' + $_.InvocationInfo.ScriptLineNumber + ': ' + (Limit-Text (($_.InvocationInfo.Line + '').Trim()) 160) + ')') -ForegroundColor DarkGray } catch {}
}
