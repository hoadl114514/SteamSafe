using System;
using System.IO;
using System.Collections.Generic;
using System.Reflection;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyVersion("0.1.2.6")]
class UninstallForm : Form {
    const string BuildProductId = "__PRODUCT_ID__";
    string productId = BuildProductId, folder, entry = "SteamSafe.exe";
    string taskName = "SteamSafeBeta", brand = "SteamSafe", dataName = "SteamSafeBeta-v0.1.2";
    CheckBox erase = new CheckBox(); Label status = new Label(), location = new Label();
    Button remove = new Button(); ComboBox installed = new ComboBox();
    class Installation {
        public string Id, Folder, Brand;
        public override string ToString() { return Brand + " — " + Folder; }
    }
    public UninstallForm() {
        folder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        Text = "卸载 SteamSafe"; ClientSize = new Size(650, 350);
        Font = new Font("Microsoft YaHei UI", 10); FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false; StartPosition = FormStartPosition.CenterScreen;
        Controls.Add(new Label { Text = "卸载 SteamSafe", Font = new Font(Font.FontFamily, 20, FontStyle.Bold), Location = new Point(25,25), AutoSize = true });
        Controls.Add(new Label { Text = "将移除所选安装、自启任务和属于该安装的快捷方式。", Location = new Point(28,80), Size = new Size(590,35) });
        location.SetBounds(28,120,590,40); location.Text = folder; Controls.Add(location);
        erase.Text = "同时删除设置、缓存和隔离备份（同名称各版本共享，不可恢复）";
        erase.SetBounds(28,169,590,32); Controls.Add(erase);
        Controls.Add(new Label { Text = "默认保留隔离和恢复材料。卸载不会删除 Steam、游戏或存档。", Location = new Point(28,210), Size = new Size(590,35) });
        status.SetBounds(28,248,590,45); Controls.Add(status);
        remove.Text = "卸载"; remove.SetBounds(420,305,90,32); remove.Click += delegate { RunUninstall(); }; Controls.Add(remove);
        var cancel = new Button { Text = "取消", Location = new Point(530,305), Size = new Size(90,32) }; cancel.Click += delegate { Close(); }; Controls.Add(cancel);
        if (BuildProductId == "REPAIR_EXISTING") {
            Text = "SteamSafe 修复卸载器"; location.Visible = false;
            installed.DropDownStyle = ComboBoxStyle.DropDownList; installed.SetBounds(28,120,590,32); Controls.Add(installed);
            using (var parent = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
                if (parent != null) foreach (string id in parent.GetSubKeyNames()) {
                    if (!id.StartsWith("SteamSafeBeta-") && !id.StartsWith("SteamSentinelBeta-")) continue;
                    using (var key = parent.OpenSubKey(id)) {
                        if (key == null) continue;
                        string path = key.GetValue("InstallLocation") as string;
                        if (!string.IsNullOrWhiteSpace(path)) installed.Items.Add(new Installation { Id=id, Folder=path, Brand=id.StartsWith("SteamSentinelBeta-") ? "Steam Sentinel" : "SteamSafe" });
                    }
                }
            }
            installed.SelectedIndexChanged += delegate {
                var choice = (Installation)installed.SelectedItem;
                productId = choice.Id; folder = Path.GetFullPath(choice.Folder); brand = choice.Brand;
                bool legacy = productId.StartsWith("SteamSentinelBeta-");
                entry = legacy ? "SteamSentinel-v0.1.2.exe" : "SteamSafe.exe";
                taskName = legacy ? "SteamSentinelBeta" : "SteamSafeBeta";
                dataName = legacy ? "SteamSentinelBeta-v0.1.2" : "SteamSafeBeta-v0.1.2";
                remove.Enabled = true;
            };
            remove.Enabled = false;
            if (installed.Items.Count > 0) installed.SelectedIndex = 0;
            else status.Text = "没有找到 SteamSafe 或 Steam Sentinel 的卸载登记。";
        }
    }
    string KeyPath { get { return @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + productId; } }
    static void RemoveLink(string link, string target) {
        if (!File.Exists(link)) return;
        SetupSecurity.NoLinks(link);
        try {
            dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
            dynamic shortcut = shell.CreateShortcut(link);
            if (string.Equals((string)shortcut.TargetPath,target,StringComparison.OrdinalIgnoreCase)) UninstallMaintenance.DeleteFile(link);
        } catch (Exception error) { if (!UninstallMaintenance.IsMissing(error)) throw; }
    }
    static void Collect(string root,string dir,List<string> dirs,List<string> files) {
        SetupSecurity.NoLinks(dir);
        foreach(string file in Directory.GetFiles(dir)) { SetupSecurity.Within(root,file.Substring(root.Length+1)); files.Add(file); }
        foreach(string child in Directory.GetDirectories(dir)) { SetupSecurity.NoLinks(child); dirs.Add(child); Collect(root,child,dirs,files); }
    }
    static void DeletePrivateData(string path) {
        SetupSecurity.NoLinks(path); if (!Directory.Exists(path)) return; SetupSecurity.ValidateAcl(path,false);
        var dirs=new List<string>(); var files=new List<string>(); Collect(path,path,dirs,files);
        foreach(string file in files) UninstallMaintenance.DeleteFile(file);
        dirs.Sort((a,b)=>b.Length.CompareTo(a.Length)); foreach(string dir in dirs) UninstallMaintenance.DeleteEmptyDirectory(dir);
        UninstallMaintenance.DeleteEmptyDirectory(path);
        if (Directory.Exists(path)) throw new IOException("私有数据目录仍有文件，请保留数据后重试");
    }
    static IEnumerable<string> TaskPaths(dynamic tasks,string name) {
        dynamic task = tasks.GetTask(name); var result = new List<string>();
        foreach (dynamic action in task.Definition.Actions) {
            // Non-executable actions have no Path property.
            if ((int)action.Type == 0) result.Add((string)action.Path);
        }
        return result;
    }
    static void QueueRemoval(string path) {
        SetupSecurity.NoLinks(path);
        if (!MoveFileEx(path,null,4)) throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error(),"无法登记重启清理："+path);
    }
    void RunUninstall() {
        string step = "验证安装目录与发行清单";
        try {
            folder=Path.GetFullPath(folder).TrimEnd('\\'); SetupSecurity.Destination(folder); SetupSecurity.NoLinks(folder);
            SetupSecurity.ValidateAcl(folder,false); SetupSecurity.ParentPolicy(folder);
            if(BuildProductId=="REPAIR_EXISTING" && Assembly.GetExecutingAssembly().Location.StartsWith(folder+"\\",StringComparison.OrdinalIgnoreCase)) throw new IOException("请将修复卸载器放在所选安装目录之外（例如下载目录）再运行");
            string menu;
            using(var key=Registry.LocalMachine.OpenSubKey(KeyPath)) {
                if(key==null || !string.Equals(folder,(string)key.GetValue("InstallLocation"),StringComparison.OrdinalIgnoreCase)) throw new IOException("卸载登记与当前目录不匹配，拒绝删除");
                menu=key.GetValue("StartMenu","") as string;
            }
            // Validate all paths before stopping processes or removing anything.
            var inventory=UninstallMaintenance.ReadInventory(folder,entry);
            string exe=Path.Combine(folder,entry);
            if (BuildProductId=="REPAIR_EXISTING" && File.Exists(exe)) SetupSecurity.CheckSignature(exe);
            if(erase.Checked) {
                using(var parent=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")) {
                    if(parent!=null) foreach(string name in parent.GetSubKeyNames()) if(name.StartsWith(taskName+"-") && name!=productId) throw new IOException("仍登记有同名称的其他版本，不能删除共享备份。请保留数据或先卸载其他版本。");
                }
                if(MessageBox.Show(this,"确认永久删除所选程序的所有设置、缓存与隔离备份？","删除私有数据",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes) return;
            }
            remove.Enabled=false; installed.Enabled=false; erase.Enabled=false; status.Text="正在卸载…"; Application.DoEvents();
            step="结束本安装的守护程序";
            foreach(var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(entry))) {
                using(process) try { if(string.Equals(process.MainModule.FileName,exe,StringComparison.OrdinalIgnoreCase)) { process.Kill(); if(!process.WaitForExit(5000)) throw new IOException("守护程序退出超时"); } } catch(InvalidOperationException) {}
            }
            step="移除自启任务";
            dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")); service.Connect(); dynamic tasks=service.GetFolder("\\");
            // Use static delegate variables to prevent dynamic binding of lambdas.
            Func<IEnumerable<string>> getPaths=()=>TaskPaths(tasks,taskName);
            Action deleteTask=()=>tasks.DeleteTask(taskName,0);
            UninstallMaintenance.RemoveOwnedTask(getPaths,deleteTask,exe);
            step="移除本安装的快捷方式";
            string menuBrand=brand=="Steam Sentinel" ? "Steam Sentinel Beta" : "SteamSafe Beta";
            RemoveLink(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),menuBrand+".lnk"),exe);
            string expectedMenu=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),menuBrand,productId);
            if(string.Equals(menu,expectedMenu,StringComparison.OrdinalIgnoreCase)) {
                RemoveLink(Path.Combine(menu,brand+".lnk"),exe); RemoveLink(Path.Combine(menu,"卸载 "+brand+".lnk"),Path.Combine(folder,"Uninstall.exe"));
                UninstallMaintenance.DeleteEmptyDirectory(menu);
            }
            step="移除发行文件";
            var dirs=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(string target in inventory) {
                if(string.Equals(target,Path.Combine(folder,"Uninstall.exe"),StringComparison.OrdinalIgnoreCase)) continue;
                string dir=Path.GetDirectoryName(target); while(dir.StartsWith(folder+"\\",StringComparison.OrdinalIgnoreCase)) { dirs.Add(dir); dir=Path.GetDirectoryName(dir); }
                UninstallMaintenance.DeleteFile(target);
            }
            var ordered=new List<string>(dirs); ordered.Sort((a,b)=>b.Length.CompareTo(a.Length)); foreach(string dir in ordered) UninstallMaintenance.DeleteEmptyDirectory(dir);
            step="清理可选私有数据";
            if(erase.Checked) DeletePrivateData(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),dataName));
            step="登记重启清理";
            // Keep the inventory until cleanup succeeds, so an interrupted uninstall can retry.
            string index=Path.Combine(folder,"release-manifest.json"), originalUninstaller=Path.Combine(folder,"Uninstall.exe");
            if(BuildProductId=="REPAIR_EXISTING") UninstallMaintenance.DeleteFile(originalUninstaller);
            else QueueRemoval(originalUninstaller);
            QueueRemoval(index);
            bool onlyQueued=true; foreach(string item in Directory.GetFileSystemEntries(folder)) if(!string.Equals(item,index,StringComparison.OrdinalIgnoreCase) && !(BuildProductId!="REPAIR_EXISTING" && string.Equals(item,originalUninstaller,StringComparison.OrdinalIgnoreCase))) onlyQueued=false;
            if(onlyQueued) QueueRemoval(folder);
            step="移除卸载登记"; Registry.LocalMachine.DeleteSubKeyTree(KeyPath,false);
            status.Text="卸载完成";
            MessageBox.Show(this,"程序已卸载。剩余发行清单、卸载器及空目录将在重启后清理；未勾选的数据继续保留。","SteamSafe"); Close();
        } catch(Exception error) {
            remove.Enabled=true; installed.Enabled=true; erase.Enabled=true; status.Text="卸载未完成："+step;
            MessageBox.Show(this,"步骤："+step+"\n"+error.GetType().Name+" · HRESULT 0x"+unchecked((uint)error.HResult).ToString("X8")+"\n\n"+error.Message,"卸载未完成",MessageBoxButtons.OK,MessageBoxIcon.Error);
        }
    }
    [System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode,SetLastError=true)] static extern bool MoveFileEx(string existing,string next,int flags);
    [STAThread] static int Main(string[] args) {
        try {
            SetupSecurity.CheckSelf(); Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            using(var form=new UninstallForm()) {
                if(args.Length==2 && args[0]=="--ui-smoke") { form.Show(); form.PerformLayout(); Application.DoEvents(); using(var bitmap=new Bitmap(form.Width,form.Height)) { form.DrawToBitmap(bitmap,new Rectangle(0,0,form.Width,form.Height)); bitmap.Save(args[1]); } return 0; }
                Application.Run(form);
            }
            return 0;
        } catch(Exception error) {
            if(args.Length>0) { Console.Error.WriteLine(error.Message); return 1; }
            MessageBox.Show(error.Message,"卸载器验证失败",MessageBoxButtons.OK,MessageBoxIcon.Error); return 1;
        }
    }
}
