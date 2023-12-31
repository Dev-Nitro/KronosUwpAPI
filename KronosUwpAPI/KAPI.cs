using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using IWshRuntimeLibrary;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using File = System.IO.File;

public class KAPI
{
    //Developed By TeamKronos
    private enum Result : uint
	{
		Success,
		DLLNotFound,
		OpenProcFail,
		AllocFail,
		LoadLibFail,
		AlreadyInjected,
		ProcNotOpen,
		Unknown
	}

    static Stopwatch stopwatch = new Stopwatch();

	private static string dll_path;

	private static IntPtr phandle;

	private static int pid = 0;

	private static readonly IntPtr NULL = IntPtr.Zero;

    [DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr OpenProcess(uint access, bool inhert_handle, int pid);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr GetModuleHandle(string lpModuleName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("bin/KFluxAPI.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern bool run_script(IntPtr proc, int pid, string path, [MarshalAs(UnmanagedType.LPWStr)] string script);

    [DllImport("bin/KFluxAPI.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern bool is_injected(IntPtr proc, int pid, string path);

    private static Result InjectDLL()
	{
        //Check if Roblox is open
		Process[] processesByName = Process.GetProcessesByName("Windows10Universal");
		if (processesByName.Length == 0) return Result.ProcNotOpen;

        //Check for dll path
        if (!File.Exists(dll_path)) return Result.DLLNotFound;

        //Check is already injected into Roblox
        if (IsInjected()) return Result.AlreadyInjected;

        //Initialize Libs
        IntPtr kernel32ModuleHandle = GetModuleHandle("kernel32.dll");
		IntPtr loadLibraryAddr = GetProcAddress(kernel32ModuleHandle, "LoadLibraryA");

		byte[] bytes = Encoding.ASCII.GetBytes(dll_path + '\0');

		object lockObject = new object();
		Result injectionResult = Result.Unknown;

        stopwatch.Start();

        Parallel.ForEach(processesByName, (process, loopState) =>
		{
			if (pid != process.Id)
			{
				IntPtr processHandle = OpenProcess(1082u, false, process.Id);
				if (processHandle == IntPtr.Zero)
				{
					lock (lockObject)
					{
						injectionResult = Result.OpenProcFail;
					}
					loopState.Break();
					return;
				}

				IntPtr remoteDllPath = VirtualAllocEx(processHandle, IntPtr.Zero, (IntPtr)bytes.Length, 0x1000 | 0x2000, 0x40);
				if (remoteDllPath == IntPtr.Zero)
				{
					lock (lockObject)
					{
						injectionResult = Result.AllocFail;
					}
					loopState.Break();
					return;
				}

				bool writeProcessMemorySuccess = WriteProcessMemory(processHandle, remoteDllPath, bytes, (IntPtr)bytes.Length, out _);
				if (!writeProcessMemorySuccess)
				{
					lock (lockObject)
					{
						injectionResult = Result.Unknown;
					}
					loopState.Break();
					return;
				}


				IntPtr threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, IntPtr.Zero, loadLibraryAddr, remoteDllPath, 0x0, IntPtr.Zero);
				if (threadHandle == IntPtr.Zero)
				{
					lock (lockObject)
					{
						injectionResult = Result.LoadLibFail;
					}
					loopState.Break();
					return;
				}

                stopwatch.Stop();
                pid = process.Id;
				phandle = processHandle;

				lock (lockObject)
				{
					injectionResult = Result.Success;
				}
				loopState.Stop();
			}
			else if (pid == process.Id)
			{
				loopState.Break();
			}
		});

        if (pid == 0) return Result.Unknown;

        return injectionResult;
	}
    public static bool IsInjected()
	{
        return is_injected(phandle, pid, dll_path);
    }

    private static bool RunScript(string script)
	{
		if (!IsInjected())
		{
			MessageBox.Show(new Form { TopMost = true }, "Please inject before executing a script.", "KAPI", MessageBoxButtons.OK, MessageBoxIcon.Warning);
			return false;
		}
        if (script == string.Empty)
        {
            return IsInjected();
        }
        return run_script(phandle, pid, dll_path, script);
    }
	public static bool Execute(string script)
	{
		try
		{
			Console.WriteLine("Checking Windows10Universal Process Length");
			if (Process.GetProcessesByName("Windows10Universal").Length < 1)
			{
				MessageBox.Show(new Form { TopMost = true }, "Please open Microsoft Store Version of ROBLOX before executing.", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return false;
			}
			Console.WriteLine("Checking Injection Status");
			RunScript(script);
			Console.WriteLine("Script Executed");
			return true;
		}
		catch
		{
			return false;
		}
	}
    private static string GetInitScript()
	{
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        using (var webClient = new WebClient())
        {
            webClient.Headers.Add(HttpRequestHeader.UserAgent, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");
            return webClient.DownloadString("https://raw.githubusercontent.com/Dev-Nitro/KronosUwpFiles/main/Lua/init.lua").ToString();
        }
    }
	public static Task<bool> Inject()
	{
        try
        {
            Console.WriteLine("Creating Folder Access");

            FileSecurity accessControl = File.GetAccessControl(dll_path);
            SecurityIdentifier identity = new SecurityIdentifier("S-1-15-2-1");
            accessControl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(dll_path, accessControl);

            Console.WriteLine("Attempting Injection...");
            switch (InjectDLL())
            {
                case Result.DLLNotFound:
                    MessageBox.Show(new Form { TopMost = true }, "Injection Failed! DLL not found!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return Task.FromResult(false);
                case Result.OpenProcFail:
                    MessageBox.Show(new Form { TopMost = true }, "Injection Failed - OpenProcFail failed!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return Task.FromResult(false);
                case Result.AllocFail:
                    MessageBox.Show(new Form { TopMost = true }, "Injection Failed - AllocFail failed!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return Task.FromResult(false);
                case Result.LoadLibFail:
                    MessageBox.Show(new Form { TopMost = true }, "Injection Failed - LoadLibFail failed!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return Task.FromResult(false);
                case Result.ProcNotOpen:
                    MessageBox.Show(new Form { TopMost = true }, "Failure to find UWP game!\n\nPlease make sure you are using the game from the Microsoft Store and not the browser!", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return Task.FromResult(false);
                case Result.Unknown:
                    MessageBox.Show(new Form { TopMost = true }, "Injection Failed - Unknown!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return Task.FromResult(false);
                case Result.AlreadyInjected:
                    MessageBox.Show(new Form { TopMost = true }, "Already Injected!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return Task.FromResult(false);
                case Result.Success:
                    Execute(GetInitScript());
                    TimeSpan elapsedTime = stopwatch.Elapsed;
                    Console.WriteLine("UWP Injection Success");
                    Console.WriteLine("Injection Time: " + elapsedTime.TotalSeconds.ToString());
                    return Task.FromResult(true);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(new Form { TopMost = true }, ex.ToString(), "KAPI Injection Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return Task.FromResult(false);
        }
        return Task.FromResult(false);
    }
    private static void CreateShortcutOnDesktop(string shortcutName)
    {
        string shortcutLocation = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + $"\\{shortcutName}.lnk";
        string targetFile = Path.GetFullPath("bin\\KAPI.Launcher.exe"); ;

        WshShell shell = new WshShell();
        IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(shortcutLocation);
        shortcut.Description = $"{shortcutName}";
        shortcut.TargetPath = targetFile;
        shortcut.Save();
    }
    private static async Task CreateShortcut(string shortcutName)
    {
        try
        {
            string shortcutLocation = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + $"\\{shortcutName}.lnk";
            if (File.Exists(shortcutLocation))
            {
                return;
            }

            CreateShortcutOnDesktop(shortcutName);
        }
        catch (Exception ex)
        {
            MessageBox.Show(new Form { TopMost = true }, $"Error Launching KAPI Client\n{ex.Message}", "KAPI Launcher Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
    }
    public static async Task<bool> LaunchKronosClient()
    {
        try
        {

            Directory.CreateDirectory("bin");
            string kapiLauncherPath = "bin\\KAPI.Launcher.exe";
            if (!File.Exists(kapiLauncherPath))
            {
                using (var client = new WebClient())
                {
                    string downloadLink = "https://github.com/Dev-Nitro/KronosUwpFiles/raw/main/Files/KAPI.Launcher.exe";
                    Console.WriteLine("Downloading KAPI.Launcher.exe...");
                    client.DownloadFile(downloadLink, kapiLauncherPath);
                }
            }
            await CreateShortcut("KAPI Client");

            string consoleAppDirectory = Path.GetDirectoryName(kapiLauncherPath);
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                WorkingDirectory = consoleAppDirectory,
                FileName = kapiLauncherPath,
                UseShellExecute = false
            };
            Process.Start(startInfo);
            return true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(new Form { TopMost = true }, $"Error Launching KAPI Client\n{ex.Message}", "KAPI Launcher Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    private static readonly string binFolderPath = "bin";

    private static readonly string dlJsonPath = Path.Combine(binFolderPath, "dl.json");

    private static readonly string dllPath = Path.Combine(binFolderPath, "Module.dll");

    private static readonly string apiPath = Path.Combine(binFolderPath, "KFluxAPI.dll");

    private static readonly string ApiUrl = "https://raw.githubusercontent.com/Dev-Nitro/KronosUwpFiles/main/KronosUwpApiData.json";

    private static readonly string WrdUrl = "https://cdn.wearedevs.net/software/jjsploit/latestdata.txt";

    private JObject latestDataCache;

    public async Task DownloadLatestDll()
    {
        try
        {
            Directory.CreateDirectory(binFolderPath);

            if (File.Exists(dlJsonPath))
            {
                File.Delete(dlJsonPath);
            }

            Console.WriteLine("Downloading Module");

            JObject latestData = GetLatestData();

            string moduleDownloadUrl, apiDownloadUrl;

            moduleDownloadUrl = (string)latestData["dll"]["downloadurl"];
            apiDownloadUrl = (string)latestData["ui"]["injDep"];

            byte[] encryptionKey = GetEncryptionKey();

            Console.WriteLine("Saving download links to encrypted JSON file (dl.json)");

            SaveDownloadLinksToEncryptedJson(moduleDownloadUrl, apiDownloadUrl, encryptionKey);

            Console.WriteLine("Reading download links from encrypted JSON file (dl.json)");

            (moduleDownloadUrl, apiDownloadUrl) = ReadDownloadLinksFromEncryptedJson(encryptionKey);

            Console.WriteLine("Downloading Module.dll");

            if (File.Exists(dllPath))
            {
                File.Delete(dllPath);
            }
            await DownloadAndSaveDll(moduleDownloadUrl, dllPath);

            Console.WriteLine("Downloading KFluxAPI.dll (if not already present)");

            if (!File.Exists(apiPath))
            {
                await DownloadAndSaveDll(apiDownloadUrl, apiPath);
            }
        }
        catch (Exception ex)
        {
            string errorMessage = "Failed to download one or more files.\n";
            errorMessage += "Exception Type: " + ex.GetType().FullName + "\n";
            errorMessage += "Message: " + ex.Message + "\n";
            if (ex.InnerException != null)
            {
                errorMessage += "Inner Exception: " + ex.InnerException.Message + "\n";
            }
            Console.WriteLine(errorMessage);
        }

        Console.WriteLine("Creating Workspace and Autoexec Folders");
        Create_files(Path.GetFullPath(dllPath));
    }

    private void SaveDownloadLinksToEncryptedJson(string moduleDownloadUrl, string apiDownloadUrl, byte[] encryptionKey)
    {
        var downloadLinks = new
        {
            ModuleUrl = moduleDownloadUrl,
            ApiUrl = apiDownloadUrl
        };

        string json = JsonConvert.SerializeObject(downloadLinks);
        byte[] encryptedData = Encrypt(json, encryptionKey);
        File.WriteAllBytes(dlJsonPath, encryptedData);
    }

    private (string ModuleUrl, string ApiUrl) ReadDownloadLinksFromEncryptedJson(byte[] encryptionKey)
    {
        byte[] encryptedData = File.ReadAllBytes(dlJsonPath);
        string decryptedJson = Decrypt(encryptedData, encryptionKey);
        var downloadLinks = JsonConvert.DeserializeObject<dynamic>(decryptedJson);

        return (downloadLinks.ModuleUrl, downloadLinks.ApiUrl);
    }

    private static byte[] GetEncryptionKey()
    {
        using (var rng = new RNGCryptoServiceProvider())
        {
            byte[] key = new byte[32];
            rng.GetBytes(key);
            return key;
        }
    }

    private byte[] Encrypt(string plainText, byte[] key)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.GenerateIV();

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }

                byte[] iv = aesAlg.IV;
                byte[] encrypted = msEncrypt.ToArray();
                byte[] result = new byte[iv.Length + encrypted.Length];
                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(encrypted, 0, result, iv.Length, encrypted.Length);

                return result;
            }
        }
    }

    private string Decrypt(byte[] cipherText, byte[] key)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            byte[] iv = new byte[aesAlg.BlockSize / 8];
            byte[] encrypted = new byte[cipherText.Length - iv.Length];

            Buffer.BlockCopy(cipherText, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(cipherText, iv.Length, encrypted, 0, encrypted.Length);

            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(encrypted))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }

    private string ReadURL(string url)
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        using (var webClient = new WebClient())
        {
            webClient.Headers.Add(HttpRequestHeader.UserAgent, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");
            return webClient.DownloadString(url);
        }
    }

    private JObject GetLatestData()
    {
        if (latestDataCache == null)
        {
            string apidownload = ReadURL(ApiUrl);
            JObject downloadtype = JObject.Parse(apidownload);
            bool WrdDownload = (bool)downloadtype["WrdDownload"];

            string text;

            if (WrdDownload)
            {
                text = ReadURL(WrdUrl);
                if (string.IsNullOrEmpty(text))
                {
                    text = apidownload;
                }
            }
            else
            {
                text = apidownload;
            }

            latestDataCache = JObject.Parse(text);
        }

        return latestDataCache;
    }

    private async Task DownloadAndSaveDll(string downloadUrl, string filePath)
    {
        using (var httpClient = new HttpClient())
        {
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");

            var dllResponse = await httpClient.GetAsync(downloadUrl);
            dllResponse.EnsureSuccessStatusCode();
            using (var dllStream = await dllResponse.Content.ReadAsStreamAsync())
            using (var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                await dllStream.CopyToAsync(fileStream);
            }
        }
    }

    private static void Create_files(string dll_path_)
	{
		if (!File.Exists(dll_path_))
		{
			MessageBox.Show(new Form { TopMost = true }, "Failure to initalize API!\nDLL path was invalid!", "Fatal Download Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
			Environment.Exit(0);
		}
		dll_path = dll_path_;
		string text = "";
		string[] directories = Directory.GetDirectories(Environment.GetEnvironmentVariable("LocalAppData") + "\\Packages");
		foreach (string text2 in directories)
		{
			if (text2.Contains("OBLOXCORPORATION") && Directory.GetDirectories(text2 + "\\AC").Any((string dir) => dir.Contains("Temp")))
			{
				text = text2 + "\\AC";
			}
		}
		if (text == "")
		{
			return;
		}
		try
		{
			if (Directory.Exists("workspace"))
			{
				Directory.Move("workspace", "old_workspace");
			}
			if (Directory.Exists("autoexec"))
			{
				Directory.Move("autoexec", "old_autoexec");
			}
		}
		catch
		{
			MessageBox.Show(new Form { TopMost = true }, "Failure to Create new Folders", "KAPI Download", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
		string text3 = Path.Combine(text, "workspace");
		string text4 = Path.Combine(text, "autoexec");
		if (!Directory.Exists(text3))
		{
			Directory.CreateDirectory(text3);
		}
		if (!Directory.Exists(text4))
		{
			Directory.CreateDirectory(text4);
		}
		if (!File.Exists("workspace.lnk"))
		{
			WshShell wshShell = (WshShell)Activator.CreateInstance(Marshal.GetTypeFromCLSID(new Guid("72C24DD5-D70A-438B-8A42-98424B88AFB8")));
			IWshShortcut obj2 = (IWshShortcut)(dynamic)wshShell.CreateShortcut("workspace.lnk");
			obj2.TargetPath = text3;
			obj2.Save();
		}
		if (!File.Exists("autoexec.lnk"))
		{
			WshShell wshShell2 = (WshShell)Activator.CreateInstance(Marshal.GetTypeFromCLSID(new Guid("72C24DD5-D70A-438B-8A42-98424B88AFB8")));
			IWshShortcut obj3 = (IWshShortcut)(dynamic)wshShell2.CreateShortcut("autoexec.lnk");
			obj3.TargetPath = text4;
			obj3.Save();
		}
    }
}
