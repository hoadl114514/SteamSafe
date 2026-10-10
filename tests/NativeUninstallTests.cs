using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

class NativeUninstallTests {
    static int count;
    static void Check(bool value, string name) { if (!value) throw new Exception(name); count++; }
    static void MustThrow(Action action, string name) { bool threw=false; try { action(); } catch { threw=true; } Check(threw,name); }
    static void Main(string[] args) {
        string root=Path.GetFullPath(args[0]); Directory.CreateDirectory(root);
        string exe=Path.Combine(root,"SteamSafe.exe"); int deletes=0;
        Check(UninstallMaintenance.IsMissing(new FileNotFoundException()),"mapped file-not-found");
        Check(UninstallMaintenance.IsMissing(new DirectoryNotFoundException()),"mapped path-not-found");
        Check(UninstallMaintenance.IsMissing(new COMException("missing",unchecked((int)0x80070002))),"COM missing");
        Check(!UninstallMaintenance.IsMissing(new UnauthorizedAccessException()),"access denied is not missing");
        Check(!UninstallMaintenance.IsMissing(new COMException("scheduler error",unchecked((int)0x8004130F))),"scheduler error preserved");
        Check(!UninstallMaintenance.RemoveOwnedTask(()=>{throw new FileNotFoundException();},()=>deletes++,exe)&&deletes==0,"no task is already clean");
        Check(!UninstallMaintenance.RemoveOwnedTask(()=>new[]{Path.Combine(root,"Other.exe")},()=>deletes++,exe)&&deletes==0,"other install task preserved");
        Check(UninstallMaintenance.RemoveOwnedTask(()=>new[]{exe.ToUpperInvariant()},()=>deletes++,exe)&&deletes==1,"owned task removed");
        Check(!UninstallMaintenance.RemoveOwnedTask(()=>new[]{exe},()=>{throw new FileNotFoundException();},exe),"task disappeared during deletion");
        MustThrow(()=>UninstallMaintenance.RemoveOwnedTask(()=>{throw new UnauthorizedAccessException();},()=>deletes++,exe),"query access error propagated");
        MustThrow(()=>UninstallMaintenance.RemoveOwnedTask(()=>new[]{exe},()=>{throw new UnauthorizedAccessException();},exe),"delete access error propagated");
        dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")); service.Connect(); dynamic tasks=service.GetFolder("\\");
        Func<IEnumerable<string>> query=()=>{tasks.GetTask("SteamSafe_ReadOnly_Test_"+Guid.NewGuid().ToString("N"));return new string[0];};
        Check(!UninstallMaintenance.RemoveOwnedTask(query,()=>{throw new Exception("must never delete a real task");},exe),"actual Windows missing-task mapping");
        UninstallMaintenance.DeleteFile(Path.Combine(root,"missing","gone.dll")); count++;
        string owned=Path.Combine(root,"owned.dll"); File.WriteAllText(owned,"fixture"); UninstallMaintenance.DeleteFile(owned); UninstallMaintenance.DeleteFile(owned); Check(!File.Exists(owned),"repeated file cleanup");
        string nonempty=Path.Combine(root,"keep"); Directory.CreateDirectory(nonempty); File.WriteAllText(Path.Combine(nonempty,"user.txt"),"keep"); UninstallMaintenance.DeleteEmptyDirectory(nonempty); Check(Directory.Exists(nonempty),"nonempty directories preserved");
        string empty=Path.Combine(root,"empty"); Directory.CreateDirectory(empty); UninstallMaintenance.DeleteEmptyDirectory(empty); UninstallMaintenance.DeleteEmptyDirectory(empty); Check(!Directory.Exists(empty),"repeated empty-directory cleanup");
        string index=Path.Combine(root,"release-manifest.json");
        File.WriteAllText(index,"{\"payload\":{\"entry\":\"SteamSafe.exe\",\"files\":{\"SteamSafe.exe\":\"hash\",\"absent.dll\":\"hash\"}}}");
        Check(UninstallMaintenance.ReadInventory(root,"SteamSafe.exe").Count==2,"inventory permits missing release files");
        MustThrow(()=>UninstallMaintenance.ReadInventory(root,"SteamSentinel-v0.1.2.exe"),"wrong product entry rejected");
        File.WriteAllText(index,"{\"payload\":{\"entry\":\"SteamSafe.exe\",\"files\":{\"SteamSafe.exe\":\"hash\",\"../escape.dll\":\"hash\"}}}");
        MustThrow(()=>UninstallMaintenance.ReadInventory(root,"SteamSafe.exe"),"escape rejected before cleanup");
        File.WriteAllText(index,"bad json"); MustThrow(()=>UninstallMaintenance.ReadInventory(root,"SteamSafe.exe"),"corrupt inventory rejected");
        File.Delete(index); MustThrow(()=>UninstallMaintenance.ReadInventory(root,"SteamSafe.exe"),"missing inventory rejected safely");
        Console.WriteLine("{\"ok\":true,\"tests\":"+count+",\"live_task_changes\":false}");
    }
}
