using Quicksilver.Managers.Main;
using Quicksilver.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;
using Object = UnityEngine.Object;

namespace Quicksilver
{
    public static class MonoLoader
    {
        public static GameObject HookObject;

        public static void Hook()
        {
            // #if DEBUG
            DebugUtilities.Log("Initializing Quicksilver...");
            // #endif        

            HookObject = new GameObject();
            Object.DontDestroyOnLoad(HookObject);
            try
            {
                AttributeManager.Init();
                //AssetManager.Init();
                //ConfigManager.Init();
            }
            catch (Exception e)
            {
                DebugUtilities.LogException(e);
            }
            //#if DEBUG
            DebugUtilities.Log("Quicksilver initialized!");
            // #endif
        }

        public static void HookThread()
        {
            while (true)
            {
                System.Threading.Thread.Sleep(10000);

                if (HookObject == null)
                    Hook();

                System.Threading.Thread.Sleep(5000);
            }
        }

        public static void Thread()
        {
            Thread thread = new Thread(HookThread);
            thread.Start();
        }
    }
}
