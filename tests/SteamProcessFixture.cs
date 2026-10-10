// Harmless integration fixture. It does not load Steam, games, or client DLLs.
using System.Threading;
class SteamProcessFixture {
    static void Main() { Thread.Sleep(30000); }
}
