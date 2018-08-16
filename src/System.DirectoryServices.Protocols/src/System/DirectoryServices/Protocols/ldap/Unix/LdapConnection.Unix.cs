using System.Net;

namespace System.DirectoryServices.Protocols
{
    public partial class LdapConnection
    {
       private IntPtr LdapOpen(string hostname, int port, bool connectionless)
        {
            throw new PlatformNotSupportedException();
        }
        
        private int SetClientCertificate()
        {
            throw new PlatformNotSupportedException();
        }


        private int LdapConnect()
        {
            throw new PlatformNotSupportedException();
        }

        private int LdapBind(NetworkCredential credential)
        {
            throw new PlatformNotSupportedException();
        }
        
        
        private int LdapSearch(SearchRequest searchRequest, int searchScope, IntPtr searchAttributes,
            string searchRequestFilter, IntPtr serverControlArray, IntPtr clientControlArray,
            int searchTimeLimit, ref int messageID)
        {
            throw new PlatformNotSupportedException();
        }

        private int LdapExtendedOperation(string name, berval berValuePtr, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageID)
        {
            throw new PlatformNotSupportedException();
        }

        private int LdapModify(string dn, IntPtr modArray, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageID)
        {
            throw new PlatformNotSupportedException();
        }

        private int LdapAdd(string dn, IntPtr modArray, IntPtr serverControlArray, IntPtr clientControlArray,
            ref int messageID)
        {
            throw new PlatformNotSupportedException();
        }

        private int LdapCompare(string dn, DirectoryAttribute attribute, string stringValue, berval berValuePtr,
            IntPtr clientControlArray, IntPtr serverControlArray, ref int messageID)
        {
            throw new PlatformNotSupportedException();
        }

        private int LdapRename(ModifyDNRequest request, IntPtr serverControlArray, IntPtr clientControlArray,
            ref int messageID)
        {
            throw new PlatformNotSupportedException();
        }

        private int LdapDelete(string dn, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageID)
        {
            throw new PlatformNotSupportedException();
        }
        
        private int LdapAbandon(int messageId)
        {
            throw new PlatformNotSupportedException();
        }

    }
}
