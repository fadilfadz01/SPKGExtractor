using Pri.LongPath;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using System.Diagnostics;
using System.Reflection;
using System.Xml.Linq;
using System.IO.Compression;
using Microsoft.WindowsPhone.ImageUpdate.PkgCommon;
using CommandLine.Text;

namespace SPKGExtractor
{
    class Program
    {
        static readonly string InternalName = Assembly.GetExecutingAssembly().GetName().Name;
        static readonly string FileVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
        static readonly string LegalCopyright = "Copyright (c) 2024";
        static readonly string CompanyName = "Fadil Fadz";
        static readonly string CurrentDirectory = Directory.GetCurrentDirectory();
        static readonly string TempDirectory = $"{Directory.GetCurrentDirectory()}\\temp";

        static string[] Packages { get; set; }
        static bool ThrowErrorAllowed { get; set; }

        static void Main(string[] args)
        {
            var parser = new Parser(with => with.CaseSensitive = false);
            var result = parser.ParseArguments<Options>(args);
            result.WithParsed(arguments =>
            {
                try
                {
                    string drive = string.Empty;
                    string output = string.Empty;

                    if (arguments.Drive.EndsWith("\\"))
                    {
                        drive = arguments.Drive.Remove(arguments.Drive.Length - 1);
                    }
                    else
                    {
                        drive = arguments.Drive;
                    }
                    if (arguments.Output.EndsWith("\\"))
                    {
                        output = arguments.Output.Remove(arguments.Output.Length - 1);
                    }
                    else
                    {
                        output = arguments.Output;
                    }
                    if (arguments.Filter != null && arguments.Filter != string.Empty)
                    {
                        if (arguments.Filter.EndsWith(';')) arguments.Filter = arguments.Filter.Remove(arguments.Filter.Length - 1);
                        var filters = arguments.Filter.Split(';');
                        Packages = new string[filters.Length];
                        for (int i = 0; i < filters.Length; i++)
                        {
                            try
                            {
                                Packages[i] = Directory.GetFiles($"{drive}\\Windows\\Packages\\DsmFiles", $"{filters[i]}.dsm.xml", System.IO.SearchOption.TopDirectoryOnly)[0];
                            }
                            catch (Exception)
                            {
                                Packages[i] = filters[i];
                            }
                        }
                    }

                    Console.WriteLine($"{InternalName} {FileVersion}");
                    Console.WriteLine($"{LegalCopyright} - {CompanyName}");
                    Console.WriteLine("");

                    Logging($"Running the {InternalName} v{FileVersion}", LoggingOption.Information);

                    if (!Directory.Exists(drive) || !Directory.Exists(output))
                        throw new System.IO.DirectoryNotFoundException("The system cannot find the path specified.");

                    Console.WriteLine($"Source: {drive}\\");
                    Console.WriteLine($"Destination: {output}");
                    try
                    {
                        if (Packages.Count() > 0)
                            Console.WriteLine("Filter: True");
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("Filter: False");
                    }
                    Console.WriteLine($"Sign: {arguments.Sign}");
                    Console.WriteLine("");

                    if (Directory.Exists(TempDirectory))
                    {
                        var ex = ForceDeleteDirectory(TempDirectory);
                        if (ex != null)
                        {
                            Logging($"Failed to wipe the directory {TempDirectory}.", LoggingOption.Warning);
                            Logging($"{ex}", LoggingOption.Exception);
                        }
                    }

                    Directory.CreateDirectory(TempDirectory);

                    if (arguments.Filter == null)
                        Packages = Directory.GetFiles($"{drive}\\Windows\\Packages\\DsmFiles", "*.xml", System.IO.SearchOption.TopDirectoryOnly);

                    Process process = new Process();
                    process.StartInfo.FileName = "certutil.exe";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.RedirectStandardInput = true;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.Arguments = "-delstore -user MY \"30 8c e4 36 9a 39 d5 8a 45 40 f9 f8 28 e9 25 97\"";
                    process.Start();
                    process.WaitForExit();
                    foreach (var certificate in Certificates)
                    {
                        GetResourceFile(certificate);
                        if (certificate.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                        {
                            process.StartInfo.Arguments = $"-p \"\" -user -importpfx \"{Path.GetTempPath()}Certificates\\{certificate}\" NoRoot";
                            process.Start();
                            process.WaitForExit();
                        }
                        else if (certificate == "OEM_Root_CA.cer" || certificate == "OEM_Root_CA2.cer")
                        {
                            process.StartInfo.Arguments = $"-addstore Root \"{Path.GetTempPath()}Certificates\\{certificate}\"";
                            process.Start();
                            process.WaitForExit();
                        }
                    }
                    process.StartInfo.Arguments = "-delstore -user MY \"30 8c e4 36 9a 39 d5 8a 45 40 f9 f8 28 e9 25 97\"";
                    process.Start();
                    process.WaitForExit();

                    int count = 0;

                    foreach (var dsmFile in Packages)
                    {
                        if (!File.Exists(dsmFile))
                        {
                            ++count;
                            Logging($"The package {Path.GetFileName(dsmFile)} does not exist in the drive {drive}\\", LoggingOption.Error);
                            Logging($"{new System.IO.FileNotFoundException("The system cannot find the file specified.")}", LoggingOption.Exception);
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {Path.GetFileName(dsmFile)}");
                            Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] The package {Path.GetFileName(dsmFile)} does not exist in the drive {drive}\\");
                            Console.ResetColor();
                            continue;
                        }

                        try
                        {
                            GzipDecompression(dsmFile, $"{TempDirectory}\\manifest.xml");
                        }
                        catch (System.IO.InvalidDataException)
                        {
                            File.Copy(dsmFile, $"{TempDirectory}\\manifest.xml", true);
                        }
                        string packageName = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(dsmFile));
                        string devicePath = string.Empty;
                        string cabPath = string.Empty;
                        string tempPackageDirectory = string.Empty;

                        bool canBreak = false;
                        ThrowErrorAllowed = true;

                        ++count;
                        Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {packageName}");

                        foreach (var Package in XElement.Load($"{TempDirectory}\\manifest.xml").Elements())
                        {
                            foreach (var files in Package.Elements().Where(w => w.Name.LocalName == "FileEntry"))
                            {
                                foreach (var fileEntry in files.Elements())
                                {
                                    if (fileEntry.Name.LocalName == "DevicePath")
                                    {
                                        devicePath = fileEntry.Value;
                                    }
                                    else if (fileEntry.Name.LocalName == "CabPath")
                                    {
                                        cabPath = fileEntry.Value;
                                    }
                                }

                                tempPackageDirectory = Directory.CreateDirectory($"{TempDirectory}\\{packageName}").FullName;

                                if (Path.GetFullPath($"{drive}{devicePath}").StartsWith($"{drive}\\WIndows\\Packages", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        GzipDecompression($"{drive}{devicePath}", $"{tempPackageDirectory}\\{cabPath}");
                                    }
                                    catch (System.IO.InvalidDataException)
                                    {
                                        File.Copy($"{drive}{devicePath}", $"{tempPackageDirectory}\\{cabPath}", true);
                                    }
                                }
                                else
                                {
                                    try
                                    {
                                        File.Copy($"{drive}{devicePath}", $"{tempPackageDirectory}\\{cabPath}");
                                    }
                                    catch (System.IO.FileNotFoundException ex)
                                    {
                                        Logging($"Couldn't find the file {drive}{devicePath} of package {packageName} from the drive {drive}\\", LoggingOption.Error);
                                        Logging($"{ex}", LoggingOption.Exception);
                                        if (ThrowErrorAllowed) StandardError($"Couldn't find the file {drive}{devicePath} from the package.", packageName, count, OutputOption.Dump);
                                        else StandardError($"Couldn't find the file {drive}{devicePath} from the package.", packageName, count, OutputOption.Error);
                                        canBreak = true;
                                    }
                                    catch (System.IO.DirectoryNotFoundException ex)
                                    {
                                        Logging($"Couldn't find the file {drive}{devicePath} of package {packageName} from the drive {drive}\\", LoggingOption.Error);
                                        Logging($"{ex}", LoggingOption.Exception);
                                        if (ThrowErrorAllowed) StandardError($"Couldn't find the file {drive}{devicePath} from the package.", packageName, count, OutputOption.Dump);
                                        else StandardError($"Couldn't find the file {drive}{devicePath} from the package.", packageName, count, OutputOption.Error);
                                        canBreak = true;
                                    }
                                    catch (Exception ex)
                                    {
                                        Logging($"Failed to dump the file {drive}{devicePath} from the package {packageName}", LoggingOption.Error);
                                        Logging($"{ex}", LoggingOption.Exception);
                                        if (ThrowErrorAllowed) StandardError($"Failed to dump the file {drive}{devicePath} from the package.", packageName, count, OutputOption.Dump);
                                        else StandardError($"Failed to dump the file {drive}{devicePath} from the package.", packageName, count, OutputOption.Error);
                                        canBreak = true;
                                    }
                                }
                            }
                        }
                        if (canBreak)
                        {
                            ForceDeleteDirectory(tempPackageDirectory);
                            continue;
                        }

                        Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Packing] {packageName}");

                        try
                        {
                            var allFiles = Directory.GetFiles(tempPackageDirectory, "*", System.IO.SearchOption.TopDirectoryOnly);
                            CabArchiver archive = new CabArchiver();

                            foreach (var allFile in allFiles)
                                archive.AddFile(allFile.Replace(tempPackageDirectory, ""), allFile);

                            archive.Save($"{output}\\{packageName}.spkg.cab", Microsoft.WindowsPhone.ImageUpdate.Tools.CompressionType.MSZip);
                        }
                        catch (Exception ex)
                        {
                            Logging($"Failed to pack the file {output}\\{packageName}.spkg.cab", LoggingOption.Error);
                            Logging($"{ex}", LoggingOption.Exception);
                            StandardError($"Failed to pack the file {output}\\{packageName}.spkg.cab", packageName, count, OutputOption.Pack);
                            if (File.Exists($"{output}\\{packageName}.spkg.cab"))
                                File.Delete($"{output}\\{packageName}.spkg.cab");
                            continue;
                        }
                        finally
                        {
                            ForceDeleteDirectory(tempPackageDirectory);
                        }

                        if (arguments.Sign)
                        {
                            Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Signing] {packageName}");

                            process.StartInfo.FileName = "SignTool.exe";
                            process.StartInfo.Arguments = $"sign /v /s my /i \"Windows Phone Intermediate 2013\" /n \"Windows Phone OEM Test Cert 2013 (TEST ONLY)\" /fd SHA256 \"{output}\\{packageName}.spkg.cab\"";
                            process.Start();
                            process.WaitForExit();

                            if (process.ExitCode != 0)
                            {
                                Logging($"Failed to sign the package {output}\\{packageName}.spkg.cab", LoggingOption.Error);
                                Logging(process.StandardError.ReadToEnd(), LoggingOption.Exception);
                                StandardError($"Failed to sign the package {output}\\{packageName}.spkg.cab", packageName, count, OutputOption.Sign);
                                if (File.Exists($"{output}\\{packageName}.spkg.cab"))
                                    File.Delete($"{output}\\{packageName}.spkg.cab");
                            }
                        }
                        ForceDeleteDirectory(tempPackageDirectory);
                    }
                }
                catch (Exception ex)
                {
                    Logging("Unhandled exception.", LoggingOption.Error);
                    Logging($"{ex}", LoggingOption.Exception);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(ex);
                    Console.ResetColor();
                }
                finally
                {
                    if (Directory.Exists($"{Path.GetTempPath()}Certificates"))
                        ForceDeleteDirectory($"{Path.GetTempPath()}Certificates");

                    var ex = ForceDeleteDirectory(TempDirectory);
                    if (ex != null)
                    {
                        Logging($"Failed to wipe the directory {TempDirectory}.", LoggingOption.Warning);
                        Logging($"{ex}", LoggingOption.Exception);
                    }
                    Logging("Exiting the SPKGExtractor.", LoggingOption.Information);
                }
            })
            .WithNotParsed(err => DisplayHelp(result));
        }

        private readonly static string[] Certificates =
        {
            "OEM_App_Test_Cert_2013.cer",
            "OEM_App_Test_Cert_2013.pfx",
            "OEM_HAL_Extension_Test_Cert_2013.cer",
            "OEM_HAL_Extension_Test_Cert_2013.pfx",
            "OEM_Intermediate_Cert.cer",
            "OEM_Intermediate_Cert.pfx",
            "OEM_Intermediate_FFU_Cert.cer",
            "OEM_Intermediate_FFU_Cert.pfx",
            "OEM_PP_Test_Cert_2013.cer",
            "OEM_PP_Test_Cert_2013.pfx",
            "OEM_PPL_Test_Cert_2013.cer",
            "OEM_PPL_Test_Cert_2013.pfx",
            "OEM_Root_CA.cer",
            "OEM_Root_CA.pfx",
            "OEM_Root_CA2.cer",
            "OEM_Test_Cert_2013.cer",
            "OEM_Test_Cert_2013.pfx",
            "OEM_Test_PK_Cert_2013.cer",
            "OEM_Test_PK_Cert_2013.pfx",
        };

        public static void GzipDecompression(string sourceFile, string destinationFile)
        {
            using (System.IO.FileStream compressedFileStream = File.OpenRead(sourceFile))
            using (System.IO.FileStream decompressedFileStream = File.Create(destinationFile))
            using (GZipStream gzipStream = new GZipStream(compressedFileStream, CompressionMode.Decompress))
            {
                byte[] buffer = new byte[4096];
                int bytesRead;

                while ((bytesRead = gzipStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    decompressedFileStream.Write(buffer, 0, bytesRead);
                }
            }
        }

        public static void GetResourceFile(string resourceName)
        {
            Directory.CreateDirectory($"{Path.GetTempPath()}Certificates");

            var embeddedResource = Assembly.GetExecutingAssembly().GetManifestResourceNames().Where(s => s.Contains(resourceName)).ToArray();

            if (!string.IsNullOrWhiteSpace(embeddedResource[0]))
            {
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(embeddedResource[0]))
                {
                    var data = new byte[stream.Length];
                    stream.Read(data, 0, data.Length);
                    File.WriteAllBytes($"{Path.GetTempPath()}Certificates\\{resourceName}", data);
                    stream.Dispose();
                }
            }
        }

        private static Exception ForceDeleteDirectory(string directory)
        {
            try
            {
                string[] files = Directory.GetFiles(directory, "*", System.IO.SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    File.SetAttributes(file, System.IO.FileAttributes.Normal);
                }

                Directory.Delete(directory, true);
                return null;
            }
            catch (Exception ex)
            {
                return ex;
            }
        }

        static void DisplayHelp<T>(ParserResult<T> result)
        {
            var helpText = HelpText.AutoBuild(result, h =>
            {
                h.MaximumDisplayWidth = 120;
                h.Heading = $"{InternalName} {FileVersion}";
                h.Copyright = $"{LegalCopyright} - {CompanyName}";
                return HelpText.DefaultParsingErrorsHandler(result, h);
            }, e => e);
            Console.WriteLine(helpText);
        }

        enum OutputOption
        {
            Error,
            Dump,
            Pack,
            Sign
        }

        static void StandardError(string errorText, string packageName, int currentCount, OutputOption option)
        {
            ThrowErrorAllowed = false;
            Console.ForegroundColor = ConsoleColor.Red;
            switch (option)
            {
                case OutputOption.Error:
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] {errorText}");
                    break;
                case OutputOption.Dump:
                    Console.SetCursorPosition(0, Console.CursorTop - 1);
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] {errorText}");
                    break;
                case OutputOption.Pack:
                    Console.SetCursorPosition(0, Console.CursorTop - 2);
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Packing] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] {errorText}");
                    break;
                case OutputOption.Sign:
                    Console.SetCursorPosition(0, Console.CursorTop - 3);
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Packing] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Signing] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] {errorText}");
                    break;
            }
            Console.ResetColor();
        }

        enum LoggingOption
        {
            Information,
            Warning,
            Error,
            Exception
        }

        static void Logging(object content, LoggingOption option)
        {
            string linesToAdd = string.Empty;
            switch (option)
            {
                case LoggingOption.Information:
                    linesToAdd = $"[{DateTime.Now:hh:mm:ss}][{option.ToString()}] {(string)content}\n";
                    break;
                case LoggingOption.Warning:
                    linesToAdd = $"[{DateTime.Now:hh:mm:ss}][  {option.ToString()}  ] {(string)content}\n";
                    break;
                case LoggingOption.Error:
                    linesToAdd = $"[{DateTime.Now:hh:mm:ss}][   {option.ToString()}   ] {(string)content}\n";
                    break;
                case LoggingOption.Exception:
                    linesToAdd = $"[{DateTime.Now:hh:mm:ss}][ {option.ToString()} ] {(string)content}\n";
                    break;
            }

            File.AppendAllText($"{CurrentDirectory}\\SPKGExtractor.log", linesToAdd);
        }

        internal class Options
        {
            [Option('d', "drive", HelpText = "A path to the source drive to dump the SPKG packages from.\nExamples. D:\\\n          D:\\EFIESP", Required = true)]
            public string Drive { get; set; }

            [Option('o', "output", HelpText = "A path to the output folder to save the SPKG packages dump.\nExamples. C:\\Users\\User\\Desktop\\Output\n          \"C:\\Users\\User\\Desktop\\SPKG Dumps\"", Required = true)]
            public string Output { get; set; }

            [Option('f', "filter", HelpText = "Optional. Dump only the given SPKG packages.\nExamples. Microsoft.MainOS.Production\n          Microsoft.MainOS.Production;Microsoft.MobileCore.Prod.MainOS;...")]
            public string Filter { get; set; }

            [Option('s', "sign", HelpText = "Optional. Test sign the output SPKG packages.", Default = false)]
            public bool Sign { get; set; }
        }
    }
}
