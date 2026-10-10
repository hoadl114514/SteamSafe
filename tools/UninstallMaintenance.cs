using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;

static class UninstallMaintenance {
    // COM interop maps HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) to
    // FileNotFoundException on Windows; it is not always a COMException.
    public static bool IsMissing(Exception error) {
        uint code = unchecked((uint)error.HResult);
        return (error is FileNotFoundException || error is DirectoryNotFoundException || error is COMException)
            && (code == 0x80070002 || code == 0x80070003);
    }
    public static bool RemoveOwnedTask(Func<IEnumerable<string>> paths, Action remove, string executable) {
        bool owned = false;
        try { foreach (string path in paths()) if (string.Equals(path, executable, StringComparison.OrdinalIgnoreCase)) owned = true; }
        catch (Exception error) { if (!IsMissing(error)) throw; return false; }
        if (!owned) return false;
        try { remove(); }
        catch (Exception error) { if (!IsMissing(error)) throw; return false; }
        return true;
    }
    public static void DeleteFile(string file) {
        SetupSecurity.NoLinks(file);
        try { File.Delete(file); }
        catch (Exception error) { if (!IsMissing(error)) throw; }
    }
    public static void DeleteEmptyDirectory(string directory) {
        SetupSecurity.NoLinks(directory);
        try { if (Directory.Exists(directory) && Directory.GetFileSystemEntries(directory).Length == 0) Directory.Delete(directory, false); }
        catch (Exception error) { if (!IsMissing(error)) throw; }
    }
    public static List<string> ReadInventory(string folder, string entry) {
        string index = SetupSecurity.Within(folder, "release-manifest.json");
        if (!File.Exists(index)) throw new IOException("发行清单缺失，无法安全确定卸载范围；未开始删除。请恢复原版发行清单后重试。");
        var serializer = new JavaScriptSerializer(); serializer.MaxJsonLength = 8 * 1024 * 1024;
        var envelope = serializer.Deserialize<Dictionary<string, object>>(File.ReadAllText(index));
        var payload = (Dictionary<string, object>)envelope["payload"];
        if (!string.Equals((string)payload["entry"], entry, StringComparison.OrdinalIgnoreCase)) throw new IOException("发行清单入口与登记的程序不匹配");
        var files = (Dictionary<string, object>)payload["files"];
        var result = new List<string>();
        foreach (string relative in files.Keys) result.Add(SetupSecurity.Within(folder, relative));
        if (!result.Exists(p => string.Equals(p, Path.Combine(folder, entry), StringComparison.OrdinalIgnoreCase))) throw new IOException("发行清单未包含主程序");
        return result;
    }
}
