using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Quicksilver.Attributes
{
	/// <summary>
	/// Attribute on a target method used to create a different thread
	/// </summary>
	[AttributeUsage(AttributeTargets.Method)]
	public class ThreadAttribute : Attribute
	{

	}
}
