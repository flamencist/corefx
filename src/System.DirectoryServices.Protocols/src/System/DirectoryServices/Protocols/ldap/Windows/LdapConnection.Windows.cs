using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace System.DirectoryServices.Protocols
{
    public partial class LdapConnection
    {
        private IntPtr LdapOpen(string hostname, int port, bool connectionless)
        {
            return connectionless ? 
                Wldap32.cldap_open(hostname, port)// User wants to setup a connectionless session with server.
                : Wldap32.ldap_init(hostname, port);
        }
        
        private int SetClientCertificate()
        {
            return Wldap32.ldap_set_option_clientcert(_ldapHandle, LdapOption.LDAP_OPT_CLIENT_CERTIFICATE, _clientCertificateRoutine);
        }
        
        
        private int LdapConnect()
        {
            // Connect explicitly to the server.
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int) (_connectionTimeOut.Ticks / TimeSpan.TicksPerSecond)
            };
            Debug.Assert(!_ldapHandle.IsInvalid);
            return Wldap32.ldap_connect(_ldapHandle, timeout);
        }
        
        private int LdapBind(NetworkCredential credential)
        {
            // Bind to the server.
            string username;
            string domainName;
            string password;
            if (credential != null && credential.UserName.Length == 0 && credential.Password.Length == 0 &&
                credential.Domain.Length == 0)
            {
                // Default credentials.
                username = null;
                domainName = null;
                password = null;
            }
            else
            {
                username = credential?.UserName;
                domainName = credential?.Domain;
                password = credential?.Password;
            }

            int error;
            if (AuthType == AuthType.Anonymous)
            {
                error = Wldap32.ldap_simple_bind_s(_ldapHandle, null, null);
            }
            else if (AuthType == AuthType.Basic)
            {
                var tempDomainName = new StringBuilder(100);
                if (!string.IsNullOrEmpty(domainName))
                {
                    tempDomainName.Append(domainName);
                    tempDomainName.Append("\\");
                }

                tempDomainName.Append(username);
                error = Wldap32.ldap_simple_bind_s(_ldapHandle, tempDomainName.ToString(), password);
            }
            else
            {
                var cred = new SEC_WINNT_AUTH_IDENTITY_EX()
                {
                    version = Wldap32.SEC_WINNT_AUTH_IDENTITY_VERSION,
                    length = Marshal.SizeOf(typeof(SEC_WINNT_AUTH_IDENTITY_EX)),
                    flags = Wldap32.SEC_WINNT_AUTH_IDENTITY_UNICODE
                };
                if (AuthType == AuthType.Kerberos)
                {
                    cred.packageList = Wldap32.MICROSOFT_KERBEROS_NAME_W;
                    cred.packageListLength = cred.packageList.Length;
                }

                if (credential != null)
                {
                    cred.user = username;
                    cred.userLength = username?.Length ?? 0;
                    cred.domain = domainName;
                    cred.domainLength = domainName?.Length ?? 0;
                    cred.password = password;
                    cred.passwordLength = password?.Length ?? 0;
                }

                BindMethod method = BindMethod.LDAP_AUTH_NEGOTIATE;
                switch (AuthType)
                {
                    case AuthType.Negotiate:
                        method = BindMethod.LDAP_AUTH_NEGOTIATE;
                        break;
                    case AuthType.Kerberos:
                        method = BindMethod.LDAP_AUTH_NEGOTIATE;
                        break;
                    case AuthType.Ntlm:
                        method = BindMethod.LDAP_AUTH_NTLM;
                        break;
                    case AuthType.Digest:
                        method = BindMethod.LDAP_AUTH_DIGEST;
                        break;
                    case AuthType.Sicily:
                        method = BindMethod.LDAP_AUTH_SICILY;
                        break;
                    case AuthType.Dpa:
                        method = BindMethod.LDAP_AUTH_DPA;
                        break;
                    case AuthType.Msn:
                        method = BindMethod.LDAP_AUTH_MSN;
                        break;
                    case AuthType.External:
                        method = BindMethod.LDAP_AUTH_EXTERNAL;
                        break;
                }

                if (credential == null && AuthType == AuthType.External)
                {
                    error = Wldap32.ldap_bind_s(_ldapHandle, null, null, method);
                }
                else
                {
                    error = Wldap32.ldap_bind_s(_ldapHandle, null, cred, method);
                }
            }

            return error;
        }
        
        
        private int LdapSearch(SearchRequest searchRequest, int searchScope, IntPtr searchAttributes,
            string searchRequestFilter, IntPtr serverControlArray, IntPtr clientControlArray,
            int searchTimeLimit, ref int messageID)
        {
            return Wldap32.ldap_search(_ldapHandle,
                searchRequest.DistinguishedName,
                searchScope,
                searchRequestFilter,
                searchAttributes,
                searchRequest.TypesOnly,
                serverControlArray,
                clientControlArray,
                searchTimeLimit,
                searchRequest.SizeLimit,
                ref messageID);
        }

        private int LdapExtendedOperation(string name, berval berValuePtr, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageID)
        {
            return Wldap32.ldap_extended_operation(_ldapHandle,
                name,
                berValuePtr,
                serverControlArray, clientControlArray, ref messageID);
        }

        private int LdapModify(string dn, IntPtr modArray, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageID)
        {
            return Wldap32.ldap_modify(_ldapHandle,
                dn,
                modArray,
                serverControlArray, clientControlArray, ref messageID);
        }

        private int LdapAdd(string dn, IntPtr modArray, IntPtr serverControlArray, IntPtr clientControlArray,
            ref int messageID)
        {
            return Wldap32.ldap_add(_ldapHandle,
                dn,
                modArray,
                serverControlArray, clientControlArray, ref messageID);
        }

        private int LdapCompare(string dn, DirectoryAttribute attribute, string stringValue, berval berValuePtr,
            IntPtr clientControlArray, IntPtr serverControlArray, ref int messageID)
        {
            return Wldap32.ldap_compare(_ldapHandle,
                dn,
                attribute.Name,
                stringValue,
                berValuePtr,
                serverControlArray, clientControlArray, ref messageID);
        }

        private int LdapRename(ModifyDNRequest request, IntPtr serverControlArray, IntPtr clientControlArray,
            ref int messageID)
        {
            return Wldap32.ldap_rename(_ldapHandle,
                request.DistinguishedName,
                request.NewName,
                request.NewParentDistinguishedName,
                request.DeleteOldRdn ? 1 : 0,
                serverControlArray, clientControlArray, ref messageID);
        }

        private int LdapDelete(string dn, IntPtr serverControlArray, IntPtr clientControlArray, ref int messageID)
        {
            return Wldap32.ldap_delete_ext(_ldapHandle, dn, serverControlArray, clientControlArray, ref messageID);
        }
        
        private int LdapAbandon(int messageId)
        {
            return Wldap32.ldap_abandon(_ldapHandle, messageId);
        }

    }
}