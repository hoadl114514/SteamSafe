using System;using System.IO;using System.Reflection;using System.Security.Principal;using System.Security.AccessControl;using System.Security;using System.Diagnostics;
class TaskHelper {
 static int Main(string[] args) {
  try {
   if(args.Length!=2)throw new Exception("参数错误");
   string folder=Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
   var security=Directory.GetAccessControl(folder);var owner=(SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
   if(owner.Value!="S-1-5-32-544"&&owner.Value!="S-1-5-18")throw new Exception("必须从受保护安装目录运行");
   foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
    string id=((SecurityIdentifier)rule.IdentityReference).Value;
    if(rule.AccessControlType==AccessControlType.Allow && id!="S-1-5-32-544"&&id!="S-1-5-18" && (rule.FileSystemRights&(FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership))!=0)throw new Exception("目录可被普通用户修改");
   }
   string sid=new SecurityIdentifier(args[1]).Value;
   if(sid!=WindowsIdentity.GetCurrent().User.Value)throw new Exception("跨账号提权不支持当前用户最高权限自启");
   dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));service.Connect();dynamic root=service.GetFolder("\\");
   if(args[0]=="disable") {try{root.DeleteTask("SteamSafeBeta",0);}catch(Exception e){if(!UninstallMaintenance.IsMissing(e))throw;}return 0;}
   if(args[0]!="enable")throw new Exception("未知操作");
   string executable=SecurityElement.Escape(Path.Combine(folder,"SteamSafe.exe"));
   string xml="<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>"+sid+"</UserId></LogonTrigger></Triggers><Principals><Principal id=\"User\"><UserId>"+sid+"</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings><Actions Context=\"User\"><Exec><Command>"+executable+"</Command><Arguments>--background</Arguments></Exec></Actions></Task>";
   string acl="O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;"+sid+")";
   root.RegisterTask("SteamSafeBeta",xml,6,null,null,3,acl);return 0;
  }catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}
 }
}
