using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using IWshRuntimeLibrary;
using Newtonsoft.Json.Linq;
using File = System.IO.File;

public class KAPI
{
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

	private WebClient Client = new WebClient();

	private static int attempts = 0;

	private static string dll_path;

	private static IntPtr phandle;

	private static int pid = 0;

	private static readonly IntPtr NULL = (IntPtr)0;

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr OpenProcess(uint access, bool inhert_handle, int pid);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, int lpNumberOfBytesWritten);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr GetModuleHandle(string lpModuleName);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

	[DllImport("bin\\KFluxAPI.dll", CallingConvention = CallingConvention.StdCall)]
	private static extern bool run_script(IntPtr proc, int pid, string path, [MarshalAs(UnmanagedType.LPWStr)] string script);

	[DllImport("bin\\KFluxAPI.dll", CallingConvention = CallingConvention.StdCall)]
	private static extern bool is_injected(IntPtr proc, int pid, string path);

	private static Result r_inject(string dll_path)
	{
		FileSecurity accessControl = File.GetAccessControl(dll_path);
		SecurityIdentifier identity = new SecurityIdentifier("S-1-15-2-1");
		accessControl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, AccessControlType.Allow));
		File.SetAccessControl(dll_path, accessControl);

		if (!File.Exists(dll_path))
		{
			return Result.DLLNotFound;
		}

		Process[] processesByName = Process.GetProcessesByName("Windows10Universal");
		if (processesByName.Length == 0)
		{
			return Result.ProcNotOpen;
		}

		IntPtr kernel32ModuleHandle = GetModuleHandle("kernel32.dll");
		IntPtr loadLibraryAddr = GetProcAddress(kernel32ModuleHandle, "LoadLibraryA");

		byte[] bytes = Encoding.UTF8.GetBytes(dll_path + '\0'); // Include null terminator in the bytes

		foreach (Process process in processesByName)
		{
			if (pid != process.Id)
			{
				IntPtr processHandle = OpenProcess(1082u, false, process.Id);
				if (processHandle == IntPtr.Zero)
				{
					return Result.OpenProcFail;
				}

				IntPtr remoteDllPath = VirtualAllocEx(processHandle, IntPtr.Zero, (IntPtr)bytes.Length, 0x1000 | 0x2000, 0x40);
				if (remoteDllPath == IntPtr.Zero)
				{
					return Result.AllocFail;
				}

				bool writeProcessMemorySuccess = WriteProcessMemory(processHandle, remoteDllPath, bytes, (IntPtr)bytes.Length, out _);
				if (!writeProcessMemorySuccess)
				{
					return Result.Unknown;
				}

				IntPtr threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, IntPtr.Zero, loadLibraryAddr, remoteDllPath, 0u, IntPtr.Zero);
				if (threadHandle == IntPtr.Zero)
				{
					return Result.LoadLibFail;
				}

				pid = process.Id;
				phandle = processHandle;
				return Result.Success;
			}
			else if (pid == process.Id)
			{
				return Result.AlreadyInjected;
			}
		}

		return Result.Unknown;
	}

	private static Result inject_custom()
	{
		try
		{
			if (!File.Exists(dll_path))
			{
				return Result.DLLNotFound;
			}
			return r_inject(dll_path);
		}
		catch
		{
			return Result.Unknown;
		}
	}

	private static void inject()
	{
		switch (inject_custom())
		{
			case Result.DLLNotFound:
				MessageBox.Show(new Form { TopMost = true }, "Injection Failed! DLL not found!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				break;
			case Result.OpenProcFail:
				MessageBox.Show(new Form { TopMost = true }, "Injection Failed - OpenProcFail failed!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				break;
			case Result.AllocFail:
				MessageBox.Show(new Form { TopMost = true }, "Injection Failed - AllocFail failed!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				break;
			case Result.LoadLibFail:
				MessageBox.Show(new Form { TopMost = true }, "Injection Failed - LoadLibFail failed!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				break;
			case Result.ProcNotOpen:
				MessageBox.Show(new Form { TopMost = true }, "Failure to find UWP game!\n\nPlease make sure you are using the game from the Microsoft Store and not the browser!", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				break;
			case Result.Unknown:
				MessageBox.Show(new Form { TopMost = true }, "Injection Failed - Unknown!\n", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				break;
			case Result.AlreadyInjected:
				break;
		}
	}
	public static bool is_injected()
	{
		return is_injected(phandle, pid, dll_path);
	}

	private static bool run_script(string script)
	{
		if (pid == 0)
		{
			MessageBox.Show(new Form { TopMost = true }, "Please press Inject first!", "KAPI", MessageBoxButtons.OK, MessageBoxIcon.Warning);
			return false;
		}
		if (script == string.Empty)
		{
			return is_injected();
		}
		return run_script(phandle, pid, dll_path, script);
	}
	public static bool Execute(string script)
	{
		try
		{
			if (Process.GetProcessesByName("Windows10Universal").Length < 1)
			{
				MessageBox.Show(new Form { TopMost = true }, "Please open Microsoft Store Version of ROBLOX before executing.", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return false;
			}
			if (!is_injected())
			{
				MessageBox.Show(new Form { TopMost = true }, "Please inject before executing a script.", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return false;
			}
			run_script(script);
			return true;
		}
		catch
		{
			return false;
		}
	}
	public static Task<bool> Inject()
	{
		TaskCompletionSource<bool> result = new TaskCompletionSource<bool>();
		try
		{
			new Thread((ThreadStart)async delegate
			{
				attempts = 0;
				Process[] processesByName = Process.GetProcessesByName("Windows10Universal");
				if (processesByName.Length < 1)
				{
					MessageBox.Show(new Form { TopMost = true }, "Failure to find UWP game!\n\nPlease make sure you are using Roblox from the Microsoft Store and not the browser!", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
					result.SetResult(result: false);
				}
				else
				{
					if (!is_injected())
					{
						try
						{
							inject();
							while (!is_injected() && attempts <= 5)
							{
								attempts++;
								await Task.Delay(500);
							}
							if (attempts >= 5)
							{
								MessageBox.Show(new Form { TopMost = true }, "KAPI is taking longer then normal to Inject. Maybe try reinjecting?", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
								result.SetResult(result: false);
							}
							else
							{
								result.SetResult(result: true);
							}
							return;
						}
						catch (Exception ex)
						{
							MessageBox.Show(ex.ToString());
							result.SetResult(result: false);
							return;
						}
					}
					MessageBox.Show(new Form { TopMost = true }, "Already Injected!", "KAPI Injection", MessageBoxButtons.OK, MessageBoxIcon.Warning);
					result.SetResult(result: false);
				}
			}).Start();
			return result.Task;
		}
		catch
		{
			result.SetResult(result: false);
			return result.Task;
		}
	}
	private string ReadURL(string url)
	{
		return Client.DownloadString(url);
	}
	private JObject latestDataCache;
	private JObject GetLatestData()
	{
		if (latestDataCache == null)
		{
			string apidownload = ReadURL("https://raw.githubusercontent.com/Dev-Nitro/KronosUwpFiles/main/KronosUwpApiData.json");
			JObject downloadtype = JObject.Parse(apidownload);
			bool WrdDownload = (bool)downloadtype["WrdDownload"];

			if (WrdDownload)
            {
				string text = ReadURL("https://cdn.wearedevs.net/software/jjsploit/latestdata.txt");
				if (text.Length <= 0)
				{
					text = ReadURL("https://raw.githubusercontent.com/Dev-Nitro/KronosUwpFiles/main/KronosUwpApiData.json");
				}
				latestDataCache = JObject.Parse(text);
			}
            else
            {
				latestDataCache = downloadtype;
            }
		}
		return latestDataCache;
	}
	private static string DLLPath = "bin\\Module.dll";

	private static string ApiPath = "bin\\KFluxAPI.dll";
	public void DownloadLatestDll()
    {
        try
        {
			Directory.CreateDirectory("bin");
			string text = (string)GetLatestData()["exploit-module"][(object)"download"];
			if (text.Length > 0)
			{
				if (File.Exists(DLLPath))
				{
					File.Delete(DLLPath);
				}
				Client.DownloadFile(text, DLLPath);
			}
			JObject latestData = GetLatestData();
			if (!File.Exists(ApiPath))
			{
				Client.DownloadFile((string)latestData["injDep"], ApiPath);
			}
		}
        catch(Exception ex)
        {
			MessageBox.Show(new Form { TopMost = true }, "Failed to download 1 or more files\n" + ex.ToString(), "KAPI", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
		create_files(Path.GetFullPath(DLLPath));
	}

	private static void create_files(string dll_path_)
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
