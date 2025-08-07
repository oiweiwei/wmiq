# wmiq

A command-line tool for querying Windows Management Instrumentation (WMI) remotely over the network using the DCOM protocol. Built with Go and leveraging the power of [RedTeamPentesting/adauth](https://github.com/RedTeamPentesting/adauth) for authentication and [oiweiwei/go-msrpc](https://github.com/oiweiwei/go-msrpc) for Microsoft RPC communication.

## Features

- **Remote WMI Queries**: Execute WQL (WMI Query Language) queries against remote Windows systems
- **Multiple Authentication Methods**: Support for username/password, Kerberos, and NT hashes
- **Flexible Transport**: Choose between TCP/IP or named pipes (SMB) transport
- **Output Formats**: JSON and YAML output support
- **Performance Optimizations**: Configurable page size, result limiting, and forward-only enumeration
- **Proxy Support**: SOCKS5 proxy support for network routing
- **Debug Mode**: Detailed debugging output for troubleshooting

## Installation

### From Source

```bash
git clone https://github.com/oiweiwei/wmiq.git
cd wmiq
go build -o wmiq wmiq.go
```

### Pre-built Binary

Check the releases page for pre-compiled binaries.

## Usage

### Basic Syntax

```bash
wmiq [options] <target> <query>
```

### Parameters

```
$ wmiq -h
Usage of wmiq:
      --aes-key hex key       Kerberos AES hex key
      --ccache file           Kerberos CCache file name (defaults to $KRB5CCNAME, currently unset)
      --dc string             Domain controller
      --debug                 Enable debug output
      --forward-only          Use forward-only enumeration
  -k, --kerberos              Use Kerberos authentication
      --limit int             Limit the number of results
      --named-pipe            Use named pipe (SMB) as transport
  -n, --namespace string      WMI namespace (resource) (default "root/cimv2")
      --no-seal               Disable sealing of DCERPC messages
  -H, --nt-hash hash          NT hash ('NT', ':NT' or 'LM:NT')
  -o, --output string         Output format (json, yaml) (default "json")
      --page int              Page size for enumeration (default 100)
  -p, --password string       Password
      --pfx file              Client certificate and private key as PFX file
      --pfx-password string   Password for PFX file
      --prototype             Return prototype
      --socks string          SOCKS5 proxy server
      --timeout duration      Timeout for the operation (default 30s)
  -u, --user user@domain      Username ('user@domain', 'domain\user', 'domain/user' or 'user')
```

## Examples

### Basic Process Query

Query running processes on a remote system:

```bash
wmiq dc01.msad.local -u username -p password "SELECT * FROM Win32_Process" -o json --limit 1
```

**Output:**
```json
{
  "CSCreationClassName": "Win32_ComputerSystem",
  "CSName": "DC01",
  "Caption": "System Idle Process",
  "CommandLine": null,
  "CreationClassName": "Win32_Process",
  "CreationDate": "20250806185811.003650-240",
  "Description": "System Idle Process",
  "Handle": "0",
  "HandleCount": 0,
  "KernelModeTime": 38191718750,
  "Name": "System Idle Process",
  "OSCreationClassName": "Win32_OperatingSystem",
  "OSName": "Microsoft Windows Server 2019 Datacenter Evaluation|C:\\Windows|\\Device\\Harddisk0\\Partition2",
  "OtherOperationCount": 0,
  "OtherTransferCount": 0,
  "PageFaults": 8,
  "PageFileUsage": 56,
  "ParentProcessId": 0,
  "PeakPageFileUsage": 56,
  "PeakVirtualSize": 8192,
  "PeakWorkingSetSize": 12,
  "Priority": 0,
  "PrivatePageCount": 57344,
  "ProcessId": 0,
  "QuotaNonPagedPoolUsage": 1,
  "QuotaPagedPoolUsage": 0,
  "QuotaPeakNonPagedPoolUsage": 1,
  "QuotaPeakPagedPoolUsage": 0,
  "ReadOperationCount": 0,
  "ReadTransferCount": 0,
  "SessionId": 0,
  "ThreadCount": 2,
  "UserModeTime": 0,
  "VirtualSize": 8192,
  "WindowsVersion": "10.0.17763",
  "WorkingSetSize": 8192,
  "WriteOperationCount": 0,
  "WriteTransferCount": 0
}
```

### System Information Query

Get operating system information:

```bash
wmiq 192.168.1.100 -u domain\\administrator -p password123 "SELECT * FROM Win32_OperatingSystem"
```

### Service Query with YAML Output

List all services in YAML format:

```bash
wmiq server.domain.com -u user@domain.com -p mypassword "SELECT Name, State, StartMode FROM Win32_Service" -o yaml --limit 5
```

### Using NT Hash Authentication

Authenticate using NT hash:

```bash
wmiq target.domain.com -u administrator -H aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 "SELECT * FROM Win32_LogicalDisk"
```

### Kerberos Authentication

Using Kerberos with a ccache file:

```bash
wmiq dc.domain.com -k --ccache /tmp/krb5cc_1000 "SELECT * FROM Win32_ComputerSystem"
```

### Named Pipe Transport

Use SMB named pipes instead of TCP:

```bash
wmiq target.domain.com -u user -p password --named-pipe "SELECT * FROM Win32_Process WHERE Name='explorer.exe'"
```

### Through SOCKS5 Proxy

Route traffic through a SOCKS5 proxy:

```bash
wmiq target.internal --socks 127.0.0.1:1080 -u domain\\user -p password "SELECT * FROM Win32_NetworkAdapter"
```

### Performance Optimization

For large result sets, use forward-only enumeration and custom page size:

```bash
wmiq server.com -u user -p pass "SELECT * FROM Win32_Process" --forward-only --page 50 --limit 100
```

## Common WMI Classes

Here are some useful WMI classes you can query:

- **Win32_Process** - Running processes
- **Win32_Service** - Windows services
- **Win32_OperatingSystem** - OS information
- **Win32_ComputerSystem** - Computer hardware info
- **Win32_LogicalDisk** - Disk drives and storage
- **Win32_NetworkAdapter** - Network adapters
- **Win32_UserAccount** - User accounts
- **Win32_Group** - Security groups
- **Win32_StartupCommand** - Startup programs
- **Win32_ScheduledJob** - Scheduled tasks
- **Win32_Share** - Network shares
- **Win32_EventLogFile** - Event logs

## WQL Query Examples

### Filter by Process Name
```sql
SELECT * FROM Win32_Process WHERE Name = 'notepad.exe'
```

### Get Specific Properties
```sql
SELECT Name, ProcessId, CommandLine FROM Win32_Process
```

### Services with Specific State
```sql
SELECT * FROM Win32_Service WHERE State = 'Running'
```

### Disk Space Information
```sql
SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3
```

## WMI Namespaces

WMI organizes classes into hierarchical namespaces. The default namespace is `root/cimv2`, but you can specify different namespaces using the `-n` or `--namespace` parameter.

### Common WMI Namespaces

- **root/cimv2** (default) - Standard CIM classes for system information
  - Win32_Process, Win32_Service, Win32_OperatingSystem, etc.
- **root/wmi** - Windows-specific WMI providers
  - Hardware monitoring, performance counters
- **root/directory/ldap** - Active Directory information
  - AD users, groups, organizational units
- **root/microsoftiisv2** - Internet Information Services (IIS)
  - Web sites, application pools, virtual directories
- **root/ccm** - System Center Configuration Manager
  - SCCM client information and policies
- **root/securitycenter** - Windows Security Center
  - Antivirus, firewall, and security product information
- **root/subscription** - Event subscriptions
  - WMI event consumers and filters

### Using Different Namespaces

Query Active Directory information:
```bash
wmiq dc.domain.com -u user -p pass -n "root/directory/ldap" "SELECT * FROM ds_user"
```

Query IIS configuration:
```bash
wmiq webserver.domain.com -u admin -p pass -n "root/microsoftiisv2" "SELECT * FROM IIsWebServer"
```

Query security center information:
```bash
wmiq target.com -u user -p pass -n "root/securitycenter" "SELECT * FROM AntiVirusProduct"
```

Query WMI performance data:
```bash
wmiq server.com -u user -p pass -n "root/wmi" "SELECT * FROM MSAcpi_ThermalZoneTemperature"
```

### Discovering Available Classes in a Namespace

To see what classes are available in a specific namespace, you can query the meta-classes:

```bash
wmiq target.com -u user -p pass -n "root/cimv2" "SELECT * FROM meta_class WHERE __class LIKE 'Win32_%DNS'"
```

## Authentication Methods

### Username/Password
```bash
-u username -p password
-u domain\\username -p password
-u username@domain.com -p password
```

### NT Hash
```bash
-u username -H ntlmhash
-u username -H lmhash:ntlmhash
```

### Kerberos Authentication

Using Kerberos with a ccache file:

```bash
wmiq dc.domain.com -k --ccache /tmp/krb5cc_1000 "SELECT * FROM Win32_ComputerSystem"
```

#### Creating a Kerberos ccache file in Linux

First, obtain a Kerberos ticket using `kinit`:

```bash
# Authenticate with domain user and specify ccache file location
kinit -c /tmp/krb5cc_wmiq user@DOMAIN.COM

# Verify ticket was obtained
klist -c /tmp/krb5cc_wmiq

# Alternative: use default location
kinit user@DOMAIN.COM
klist
```

Then use wmiq with the ccache file:

```bash
# Use a specific ccache file
wmiq dc.domain.com -k --ccache /tmp/krb5cc_wmiq "SELECT * FROM Win32_Process" --limit 5

# Or use the default ccache location (wmiq will auto-detect)
wmiq dc.domain.com -k "SELECT * FROM Win32_Process" --limit 5
```

Example complete workflow:
```bash
# Obtain Kerberos ticket with specific ccache file
kinit -c /tmp/krb5cc_wmiq administrator@CONTOSO.COM
# Password: ********

# Verify ticket
klist -c /tmp/krb5cc_wmiq
# Ticket cache: FILE:/tmp/krb5cc_wmiq
# Default principal: administrator@CONTOSO.COM

# Query WMI using Kerberos authentication
wmiq dc01.contoso.com -k --ccache /tmp/krb5cc_wmiq "SELECT Name, State FROM Win32_Service WHERE State='Running'" --limit 3
```

#### Using AES Key with Kerberos

If you have an AES key instead of a password, you can use it directly:

```bash
# Using AES-256 key (hex format)
wmiq dc01.contoso.com -k --aes-key a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456 "SELECT * FROM Win32_Process" --limit 5

# Combined with ccache file
wmiq dc01.contoso.com -k --ccache /tmp/krb5cc_wmiq --aes-key a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456 "SELECT * FROM Win32_ComputerSystem"
```

## Troubleshooting

### Enable Debug Output
Use the `--debug` flag to see detailed protocol communication:

```bash
wmiq target.com -u user -p pass "SELECT * FROM Win32_Process" --debug
```

### Common Issues

1. **Access Denied**: Ensure the user has WMI query permissions on the target system
2. **Authentication Failures**: Verify credentials and try different authentication methods
3. **Large Result Sets**: Use `--limit` and `--page` parameters to manage memory usage

## Dependencies

- [RedTeamPentesting/adauth](https://github.com/RedTeamPentesting/adauth) - Active Directory authentication
- [oiweiwei/go-msrpc](https://github.com/oiweiwei/go-msrpc) - Microsoft RPC protocol implementation

## License

This project is licensed under the terms specified in the LICENSE file.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Security Considerations

- This tool can be used for legitimate system administration and security testing
- Always ensure you have proper authorization before querying remote systems
- Be mindful of credentials and use secure authentication methods when possible
- Consider using SOCKS5 proxies in sensitive network environments

## Useful Resources

### WQL Reference and Documentation

- **[WQL (SQL for WMI) Reference](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)** - Official Microsoft WQL documentation
- **[WMI Classes Reference](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-provider)** - Complete list of Win32 WMI classes
- **[WQL Operators](https://learn.microsoft.com/en-us/windows/win32/wmisdk/where-clause)** - WHERE clause operators and syntax
- **[WMI Query Language by Example](https://www.codeproject.com/Articles/46390/WMI-Query-Language-by-Example)** - Practical WQL examples and syntax guide