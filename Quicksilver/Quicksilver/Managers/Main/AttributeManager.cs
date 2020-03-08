using Quicksilver.Attributes;
using Quicksilver.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Quicksilver.Managers.Main
{
    public static class AttributeManager
    {

        public static void Init()
        {
            // #if DEBUG
            DebugUtilities.Log("Initializing attribute manager...");
            //#endif

            // Declare lists to be populated later
            List<Type> Components = new List<Type>();
            List<MethodInfo> Pre = new List<MethodInfo>();
            List<MethodInfo> Post = new List<MethodInfo>();

            foreach (Type T in Assembly.GetExecutingAssembly().GetTypes())
            {
                //// Collect and add components marked with the attribute
                //if (T.IsDefined(typeof(ComponentAttribute), false))
                //    Ldr.HookObject.AddComponent(T);

                //// Collect components to be destroyed on spy
                //if (T.IsDefined(typeof(SpyComponentAttribute), false))
                //    Components.Add(T);

                foreach (MethodInfo M in T.GetMethods())
                {
                    //// Collect and invoke methods marked to be initialized
                    //if (M.IsDefined(typeof(InitializerAttribute), false))
                    //    M.Invoke(null, null);

                    //// Collect and override methods marked with the attribute
                    //if (M.IsDefined(typeof(OverrideAttribute), false))
                    //    OverrideManager.LoadOverride(M);

                    //// Collect methods to be invoked before spy
                    //if (M.IsDefined(typeof(OnSpyAttribute), false))
                    //    Pre.Add(M);

                    //// Collect methods to be invoked after spy
                    //if (M.IsDefined(typeof(OffSpyAttribute), false))
                    //    Post.Add(M);

                    // Collect and thread methods marked with the attribute
                    if (M.IsDefined(typeof(ThreadAttribute), false))
                    {
                        new Thread(() =>
                        {
                            try
                            {
                                M.Invoke(null, null);
                            }
                            catch (Exception e)
                            {
                                DebugUtilities.Log("START THREAD ERROR: " + e);
                            }
                        }).Start();
                    }
                }
            }

            // Assign all variables
            //SpyManager.Components = Components;
            //SpyManager.PostSpy = Post;
            //SpyManager.PreSpy = Pre;

            //#if DEBUG
            DebugUtilities.Log("Attribute manager initialized.");
            //#endif
        }
    }
}
