using System;
using System.Globalization;
using System.IO;
using System.Text;

#if SILVERLIGHT
using System.Collections.Generic;
#else
using System.Collections;
#endif

namespace Org.BouncyCastle.Utilities
{
    internal abstract class Platform
    {

        internal static int CompareIgnoreCase(string a, string b)
        {
            return String.Compare(a, b, true);
        }


        internal static string GetEnvironmentVariable(
            string variable)
        {
            try
            {
                return Environment.GetEnvironmentVariable(variable);
            }
            catch (System.Security.SecurityException)
            {
                // We don't have the required permission to read this environment variable,
                // which is fine, just act as if it's not set
                return null;
            }
        }



        internal static Exception CreateNotImplementedException(string message)
        {
            return new NotImplementedException(message);
        }


        internal static System.Collections.IList CreateArrayList()
        {
            return new ArrayList();
        }

        internal static System.Collections.IList CreateArrayList(int capacity)
        {
            return new ArrayList(capacity);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            return new ArrayList(collection);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            ArrayList result = new ArrayList();
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Hashtable();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Hashtable(capacity);
        }
        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            return new Hashtable(dictionary);
        }


        internal static string ToLowerInvariant(string s)
        {
            return s.ToLower(CultureInfo.InvariantCulture);
        }

        internal static string ToUpperInvariant(string s)
        {
            return s.ToUpper(CultureInfo.InvariantCulture);
        }

    }

}
