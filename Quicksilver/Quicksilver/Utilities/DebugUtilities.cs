using Quicksilver.Attributes;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Quicksilver.Utilities
{
    public static class DebugUtilities
    {
        public static ConcurrentQueue<string> Data = new ConcurrentQueue<string>();

        [Thread]
        public static void DebugThread()
        {
            File.WriteAllText("qs.log", "");
            Data.Enqueue($"Quicksilver Debug Init Start: {DateTime.Now}\r\n\r\n");

            while (true)
            {
                Thread.Sleep(500);
                while (Data.Count > 0)
                    if (Data.TryDequeue(out string str))
                        File.AppendAllText("qs.log", str);
            }
        }

        public static void Log(object Output) =>
            Data.Enqueue($"{Output}\r\n");

        public static void LogException(Exception Exception) =>
            Data.Enqueue($"\r\nBEGIN EXCEPTION\r\n{Exception}\r\nEND EXCEPTION\r\n");
    }
}
