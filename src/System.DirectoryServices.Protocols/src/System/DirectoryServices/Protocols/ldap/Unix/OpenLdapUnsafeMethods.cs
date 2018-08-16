using System.Runtime.InteropServices;

namespace System.DirectoryServices.Protocols
{
    /// <summary>
    /// LDAP_OPTions
    /// 0x0000 - 0x0fff reserved for api options
    /// 0x1000 - 0x3fff reserved for api extended options
    /// 0x4000 - 0x7fff reserved for private and experimental options
    /// </summary>
    internal enum OpenLdapOption
        {
            LDAP_OPT_API_INFO = 0x0000,
            LDAP_OPT_DESC = 0x0001, /* historic */
            LDAP_OPT_DEREF = 0x0002,
            LDAP_OPT_SIZELIMIT = 0x0003,
            LDAP_OPT_TIMELIMIT = 0x0004,

            /* 0x05 - 0x07 not defined */
            LDAP_OPT_REFERRALS = 0x0008,
            LDAP_OPT_RESTART = 0x0009,

            /* 0x0a - 0x10 not defined */
            LDAP_OPT_PROTOCOL_VERSION = 0x0011,
            LDAP_OPT_SERVER_CONTROLS = 0x0012,
            LDAP_OPT_CLIENT_CONTROLS = 0x0013,

            /* 0x14 not defined */
            LDAP_OPT_API_FEATURE_INFO = 0x0015,

            /* 0x16 - 0x2f not defined */
            LDAP_OPT_HOST_NAME = 0x0030,
            LDAP_OPT_RESULT_CODE = 0x0031,
            LDAP_OPT_ERROR_NUMBER = LDAP_OPT_RESULT_CODE,
            LDAP_OPT_DIAGNOSTIC_MESSAGE = 0x0032,
            LDAP_OPT_ERROR_STRING = LDAP_OPT_DIAGNOSTIC_MESSAGE,
            LDAP_OPT_MATCHED_DN = 0x0033,

            /* 0x0034 - 0x3fff not defined */
            /* 0x0091 used by Microsoft for LDAP_OPT_AUTO_RECONNECT */
            LDAP_OPT_SSPI_FLAGS = 0x0092,

            /* 0x0093 used by Microsoft for LDAP_OPT_SSL_INFO */
            /* 0x0094 used by Microsoft for LDAP_OPT_REF_DEREF_CONN_PER_MSG */
            LDAP_OPT_SIGN = 0x0095,
            LDAP_OPT_ENCRYPT = 0x0096,
            LDAP_OPT_SASL_METHOD = 0x0097,

            /* 0x0098 used by Microsoft for LDAP_OPT_AREC_EXCLUSIVE */
            LDAP_OPT_SECURITY_CONTEXT = 0x0099,

            /* 0x009A used by Microsoft for LDAP_OPT_ROOTDSE_CACHE */
            /* 0x009B - 0x3fff not defined */
            /* API Extensions */
            LDAP_OPT_API_EXTENSION_BASE = 0x4000, /* API extensions */

            /* private and experimental options */
            /* OpenLDAP specific options */
            LDAP_OPT_DEBUG_LEVEL = 0x5001, /* debug level */
            LDAP_OPT_TIMEOUT = 0x5002, /* default timeout */
            LDAP_OPT_REFHOPLIMIT = 0x5003, /* ref hop limit */
            LDAP_OPT_NETWORK_TIMEOUT = 0x5005, /* socket level timeout */
            LDAP_OPT_URI = 0x5006,
            LDAP_OPT_REFERRAL_URLS = 0x5007, /* Referral URLs */
            LDAP_OPT_SOCKBUF = 0x5008, /* sockbuf */
            LDAP_OPT_DEFBASE = 0x5009, /* searchbase */
            LDAP_OPT_CONNECT_ASYNC = 0x5010, /* create connections asynchronously */
            LDAP_OPT_CONNECT_CB = 0x5011, /* connection callbacks */
            LDAP_OPT_SESSION_REFCNT = 0x5012, /* session reference count */

            /* OpenLDAP TLS options */
            LDAP_OPT_X_TLS = 0x6000,
            LDAP_OPT_X_TLS_CTX = 0x6001, /* OpenSSL CTX* */
            LDAP_OPT_X_TLS_CACERTFILE = 0x6002,
            LDAP_OPT_X_TLS_CACERTDIR = 0x6003,
            LDAP_OPT_X_TLS_CERTFILE = 0x6004,
            LDAP_OPT_X_TLS_KEYFILE = 0x6005,
            LDAP_OPT_X_TLS_REQUIRE_CERT = 0x6006,
            LDAP_OPT_X_TLS_PROTOCOL_MIN = 0x6007,
            LDAP_OPT_X_TLS_CIPHER_SUITE = 0x6008,
            LDAP_OPT_X_TLS_RANDOM_FILE = 0x6009,
            LDAP_OPT_X_TLS_SSL_CTX = 0x600a, /* OpenSSL SSL* */
            LDAP_OPT_X_TLS_CRLCHECK = 0x600b,
            LDAP_OPT_X_TLS_CONNECT_CB = 0x600c,
            LDAP_OPT_X_TLS_CONNECT_ARG = 0x600d,
            LDAP_OPT_X_TLS_DHFILE = 0x600e,
            LDAP_OPT_X_TLS_NEWCTX = 0x600f,
            LDAP_OPT_X_TLS_CRLFILE = 0x6010, /* GNUtls only */
            LDAP_OPT_X_TLS_PACKAGE = 0x6011,
            LDAP_OPT_X_TLS_NEVER = 0,
            LDAP_OPT_X_TLS_HARD = 1,
            LDAP_OPT_X_TLS_DEMAND = 2,
            LDAP_OPT_X_TLS_ALLOW = 3,
            LDAP_OPT_X_TLS_TRY = 4,
            LDAP_OPT_X_TLS_CRL_NONE = 0,
            LDAP_OPT_X_TLS_CRL_PEER = 1,
            LDAP_OPT_X_TLS_CRL_ALL = 2,

            ///* OpenLDAP SASL options */
            LDAP_OPT_X_SASL_MECH = 0x6100,
            LDAP_OPT_X_SASL_REALM = 0x6101,
            LDAP_OPT_X_SASL_AUTHCID = 0x6102,
            LDAP_OPT_X_SASL_AUTHZID = 0x6103,
            LDAP_OPT_X_SASL_SSF = 0x6104, /* read-only */
            LDAP_OPT_X_SASL_SSF_EXTERNAL = 0x6105, /* write-only */
            LDAP_OPT_X_SASL_SECPROPS = 0x6106, /* write-only */
            LDAP_OPT_X_SASL_SSF_MIN = 0x6107,
            LDAP_OPT_X_SASL_SSF_MAX = 0x6108,
            LDAP_OPT_X_SASL_MAXBUFSIZE = 0x6109,
            LDAP_OPT_X_SASL_MECHLIST = 0x610a, /* read-only */
            LDAP_OPT_X_SASL_NOCANON = 0x610b,
            LDAP_OPT_X_SASL_USERNAME = 0x610c, /* read-only */
            LDAP_OPT_X_SASL_GSS_CREDS = 0x610d,

            /* OpenLDAP GSSAPI options */
            LDAP_OPT_X_GSSAPI_DO_NOT_FREE_CONTEXT = 0x6200,
            LDAP_OPT_X_GSSAPI_ALLOW_REMOTE_PRINCIPAL = 0x6201,

            /*
             * OpenLDAP per connection tcp-keepalive settings
             * (Linux only, ignored where unsupported)
             */
            LDAP_OPT_X_KEEPALIVE_IDLE = 0x6300,
            LDAP_OPT_X_KEEPALIVE_PROBES = 0x6301,
            LDAP_OPT_X_KEEPALIVE_INTERVAL = 0x6302,

            /* Private API Extensions -- reserved for application use */
            LDAP_OPT_PRIVATE_EXTENSION_BASE = 0x7000, /* Private API inclusive */

            /*
             * ldap_get_option() and ldap_set_option() return values.
             * As later versions may return other values indicating
             * failure, current applications should only compare returned
             * value against LDAP_OPT_SUCCESS.
             */
            LDAP_OPT_SUCCESS = 0,
            LDAP_OPT_ERROR = -1
        }

    internal class OpenLdapUnsafeMethods
    {
        private const string LIB_LDAP_PATH = "libldap-2.4.so.2";
        public delegate int LDAP_SASL_INTERACT_PROC(IntPtr ld, uint flags, IntPtr defaults, IntPtr interact);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_initialize(ref IntPtr ld, string uri);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_simple_bind_s(IntPtr ld, string who, string cred);

        /// <summary>
        /// ldap_sasl_interactive_bind_s <a href="https://linux.die.net/man/3/ldap_sasl_bind_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mechanism">const char           *mechanism</param>
        /// <param name="serverctrls">LDAPControl         **serverctrls</param>
        /// <param name="clientctrls">LDAPControl         **clientctrls</param>
        /// <param name="flags">unsigned flags </param>
        /// <param name="proc">delegate</param>
        /// <param name="defaults">void *defaults</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_sasl_interactive_bind_s(IntPtr ld, string dn, string mechanism,
            IntPtr serverctrls, IntPtr clientctrls, uint flags,
            [MarshalAs(UnmanagedType.FunctionPtr)] LDAP_SASL_INTERACT_PROC proc, IntPtr defaults);

        /// <summary>
        /// ldap_sasl_bind_s <a href="https://linux.die.net/man/3/ldap_sasl_bind_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mechanism">const char           *mechanism</param>
        /// <param name="cred">const struct berval  *cred</param>
        /// <param name="serverctrls">LDAPControl         **serverctrls</param>
        /// <param name="clientctrls">LDAPControl         **clientctrls</param>
        /// <param name="servercredp">struct berval       **servercredp</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_sasl_bind_s(IntPtr ld, string dn, string mechanism,
            IntPtr cred, IntPtr serverctrls, IntPtr clientctrls, IntPtr servercredp);
       
        
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_set_option(IntPtr ld, int option, [In] ref int invalue);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_set_option(IntPtr ld, int option, [In] ref string invalue);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_set_option(IntPtr ld, int option, IntPtr invalue);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_get_option(IntPtr ld, int option, ref string value);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_get_option(IntPtr ld, int option, ref IntPtr value);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_unbind_s(IntPtr ld);

        /// <summary>
        /// ldap_search_ext_s <a href="https://linux.die.net/man/3/ldap_search_ext_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="base">char *base</param>
        /// <param name="scope">int scope</param>
        /// <param name="filter">char *filter</param>
        /// <param name="attrs">char *attrs[]</param>
        /// <param name="attrsonly">int attrsonly</param>
        /// <param name="serverctrls">LDAPControl **serverctrls</param>
        /// <param name="clientctrls">LDAPControl **clientctrls</param>
        /// <param name="timeout">struct timeval *timeout</param>
        /// <param name="sizelimit">int sizelimit</param>
        /// <param name="pMessage">LDAPMessage **res</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_search_ext_s(IntPtr ld, string @base, int scope, string filter, string[] attrs,
            int attrsonly, IntPtr serverctrls, IntPtr clientctrls, IntPtr timeout, int sizelimit, ref IntPtr pMessage);


        [DllImport(LIB_LDAP_PATH)]
        private static extern IntPtr ldap_err2string(int error);

        public static string LdapError2String(int error)
        {
            return Marshal.PtrToStringAnsi(ldap_err2string(error));
        }


        public static string GetAdditionalErrorInfo(IntPtr ld)
        {
            var ptr = Marshal.AllocHGlobal(IntPtr.Size);
            ldap_get_option(ld,(int)OpenLdapOption.LDAP_OPT_DIAGNOSTIC_MESSAGE,ref ptr);
            var info = Marshal.PtrToStringAnsi(ptr);
            ldap_memfree(ptr);
            return info;
        }


        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_count_entries(IntPtr ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_first_entry(IntPtr ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_next_entry(IntPtr ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_get_dn(IntPtr ld, IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern void ldap_memfree(IntPtr ptr);

        [DllImport(LIB_LDAP_PATH)]
        public static extern void ldap_msgfree(IntPtr message);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_first_attribute(IntPtr ld, IntPtr entry, ref IntPtr ppBer);

        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_next_attribute(IntPtr ld, IntPtr entry, IntPtr pBer);

        [DllImport(LIB_LDAP_PATH)]
        public static extern void ldap_value_free(IntPtr vals);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_count_values(IntPtr vals);
        
        [DllImport(LIB_LDAP_PATH)]
        public static extern IntPtr ldap_get_values(IntPtr ld, IntPtr entry, IntPtr pBer);
        
        /// <summary>
        /// ldap_add_ext_s <a href="https://linux.die.net/man/3/ldap_add">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char *dn</param>
        /// <param name="attrs">LDAPMod **attrs</param>
        /// <param name="serverctrls">LDAPControl  **serverctrls</param>
        /// <param name="clientctrls">LDAPControl  **clientctrls</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_add_ext_s(IntPtr ld, string dn, IntPtr attrs , IntPtr serverctrls, IntPtr clientctrls);
        
        /// <summary>
        /// ldap_modify_ext_s <a href="https://linux.die.net/man/3/ldap_modify_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="mods">LDAPMod *mods[]</param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_modify_ext_s(IntPtr ld, string dn,IntPtr mods , IntPtr serverctrls, IntPtr clientctrls);
        
        /// <summary>
        /// ldap_delete_ext_s <a href="https://linux.die.net/man/3/ldap_delete_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char           *dn</param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_delete_ext_s(IntPtr ld, string dn, IntPtr serverctrls, IntPtr clientctrls);

        /// <summary>
        /// ldap_compare_ext_s <a href="https://linux.die.net/man/3/ldap_compare_ext_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char   *dn</param>
        /// <param name="attr">char *attr</param>
        /// <param name="bvalue">const struct berval  *bvalue</param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_compare_ext_s(IntPtr ld, string dn, string attr, IntPtr bvalue, IntPtr serverctrls, IntPtr clientctrls);

        /// <summary>
        /// ldap_rename_s <a href="https://linux.die.net/man/3/ldap_rename_s">Documentation</a>
        /// </summary>
        /// <param name="ld">LDAP *ld</param>
        /// <param name="dn">const char   *dn</param>
        /// <param name="newrdn">const char *newrdn</param>
        /// <param name="deleteoldrdn"></param>
        /// <param name="serverctrls">LDAPControl     **serverctrls</param>
        /// <param name="clientctrls">LDAPControl     **clientctrls</param>
        /// <param name="newparent"></param>
        /// <returns>result code</returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_rename_s(IntPtr ld, string dn, string newrdn, string newparent, int deleteoldrdn, IntPtr serverctrls, IntPtr clientctrls);

        /// <summary>
        /// ldap_is_ldap_url <a href="https://linux.die.net/man/3/ldap_is_ldap_url">Documentation</a>
        /// </summary>
        /// <param name="url">const char *url</param>
        /// <returns></returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_is_ldap_url(string url);

        /// <summary>
        /// ldap_url_parse <a href="https://linux.die.net/man/3/ldap_url_parse">Documentation</a>
        /// </summary>
        /// <param name="url">const char *url</param>
        /// <param name="ludpp">LDAPURLDesc **ludpp </param>
        /// <returns></returns>
        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_url_parse(string url, ref IntPtr ludpp);

        [DllImport(LIB_LDAP_PATH)]
        public static extern int ldap_free_urldesc(string url, ref IntPtr ludpp);
    }
}