package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/RedTeamPentesting/adauth"
	"github.com/RedTeamPentesting/adauth/dcerpcauth"

	"github.com/oiweiwei/go-msrpc/dcerpc"

	"github.com/oiweiwei/go-msrpc/msrpc/dcetypes"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iremunknown2/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmio"

	wmi_client "github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/client"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/ienumwbemclassobject/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemfetchsmartenum/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemlevel1login/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemservices/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wmi/iwbemwcosmartenum/v0"

	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/wmi"
)

func run() error {
	var (
		debug       bool
		socksServer = os.Getenv("SOCKS5_SERVER")
		authOpts    = &adauth.Options{
			Debug: adauth.NewDebugFunc(&debug, os.Stderr, true),
		}
		dcerpcauthOpts = &dcerpcauth.Options{
			Debug: authOpts.Debug,
		}
		namedPipe    bool
		prototype    bool
		forward      bool
		limit        int
		page         int
		namespace    string
		query        string
		outputFormat string
		noSeal       bool
		timeout      time.Duration
	)

	pflag.CommandLine.BoolVar(&debug, "debug", false, "Enable debug output")
	pflag.CommandLine.StringVar(&socksServer, "socks", socksServer, "SOCKS5 proxy server")
	pflag.CommandLine.BoolVar(&namedPipe, "named-pipe", false, "Use named pipe (SMB) as transport")
	pflag.CommandLine.BoolVar(&prototype, "prototype", false, "Return prototype")
	pflag.CommandLine.BoolVar(&forward, "forward-only", false, "Use forward-only enumeration")
	pflag.CommandLine.IntVar(&limit, "limit", 0, "Limit the number of results")
	pflag.CommandLine.IntVar(&page, "page", 100, "Page size for enumeration")
	pflag.CommandLine.StringVarP(&namespace, "namespace", "n", "root/cimv2", "WMI namespace (resource)")
	pflag.CommandLine.StringVarP(&outputFormat, "output", "o", "json", "Output format (json, yaml)")
	pflag.CommandLine.BoolVar(&noSeal, "no-seal", false, "Disable sealing of DCERPC messages")
	pflag.CommandLine.DurationVar(&timeout, "timeout", 30*time.Second, "Timeout for the operation")

	authOpts.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	logger := zerolog.New(io.Discard)

	if debug {
		logger = zerolog.New(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.Out = os.Stderr
			w.TimeFormat = time.DateTime
		})).With().Timestamp().Logger()

		authOpts.Debug = logger.Printf
		dcerpcauthOpts.Debug = logger.Printf
	}

	if len(pflag.Args()) != 2 {
		return fmt.Errorf("usage: %s [options] <target> <query>", binaryName())
	}

	writer := newEncoder(outputFormat)

	dcerpcauthOpts.KerberosDialer = adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil)

	creds, target, err := authOpts.WithTarget(context.Background(), "host", pflag.Arg(0))
	if err != nil {
		return err
	}

	if query = pflag.Arg(1); query == "" {
		return fmt.Errorf("usage: %s [options] <target> <query>", binaryName())
	}

	ctx := context.Background()

	dcerpcOpts, err := dcerpcauth.AuthenticationOptions(ctx, creds, target, dcerpcauthOpts)
	if err != nil {
		return err
	}

	dcerpcOpts = append(dcerpcOpts,
		dcerpc.WithDialer(adauth.DialerWithSOCKS5ProxyIfSet(socksServer, nil)),
		dcerpc.WithTimeout(timeout),
		dcerpc.WithLogger(logger),
		well_known.EndpointMapper(),
	)

	proto := "ncacn_ip_tcp"
	if namedPipe {
		proto = "ncacn_np"
	}

	conn, err := dcerpc.Dial(ctx, target.Address(), dcerpcOpts...)
	if err != nil {
		return fmt.Errorf("dial DCERPC: %w", err)
	}

	defer conn.Close(ctx) //nolint:errcheck

	authOpt := dcerpc.WithSeal()
	if noSeal {
		authOpt = dcerpc.WithSign()
	}

	exporterCli, err := iobjectexporter.NewObjectExporterClient(ctx, conn, authOpt)
	if err != nil {
		return fmt.Errorf("create IObjectExporter client: %w", err)
	}

	srv, err := exporterCli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		return fmt.Errorf("IObjectExporter.ServerAlive2: %w", err)
	}

	activationCli, err := iactivation.NewActivationClient(ctx, conn, authOpt)
	if err != nil {
		return fmt.Errorf("create IActivation client: %w", err)
	}

	act, err := activationCli.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    wmi.Level1LoginClassID.GUID(),
		IIDs:                       []*dcom.IID{iwbemlevel1login.Level1LoginIID},
		RequestedProtocolSequences: []uint16{(uint16)(dcetypes.ProtocolTCP), (uint16)(dcetypes.ProtocolNamedPipe)},
	})

	if err != nil {
		return fmt.Errorf("IActivation.RemoteActivation: %w", err)
	}

	if act.HResult != 0 {
		return fmt.Errorf("remote activation failed: %w", hresult.FromCode(uint32(act.HResult)))
	}

	for _, binding := range act.OXIDBindings.GetStringBindings() {
		dcerpcauthOpts.Debug("found binding: %s", binding)
	}

	dcerpcOpts = append(dcerpcOpts, act.OXIDBindings.EndpointsByProtocol(proto)...)

	wcc, err := dcerpc.Dial(ctx, target.Address(), dcerpcOpts...)
	if err != nil {
		return fmt.Errorf("dial_wmi_endpoint: %w", err)
	}

	defer wcc.Close(ctx) // nolint:errcheck

	wmiCli, err := wmi_client.NewClient(ctx, wcc, authOpt)
	if err != nil {
		return fmt.Errorf("create WMI client: %w", err)
	}

	// login to WMI.
	login, err := wmiCli.Level1Login().NTLMLogin(ctx, &iwbemlevel1login.NTLMLoginRequest{
		This:            &dcom.ORPCThis{Version: srv.COMVersion},
		NetworkResource: namespace,
	}, dcom.WithIPID(act.InterfaceData[0].IPID()))

	if err != nil {
		return fmt.Errorf("ILevel1Login.NTLMLogin: %w", err)
	}

	flags := wmi.QueryFlagType(0)

	if prototype {
		flags |= wmi.QueryFlagTypePrototype
	}

	if forward {
		flags |= wmi.QueryFlagType(wmi.GenericFlagTypeForwardOnly)
	}

	enum, err := wmiCli.Services().ExecQuery(ctx, &iwbemservices.ExecQueryRequest{
		This:          &dcom.ORPCThis{Version: srv.COMVersion},
		QueryLanguage: &oaut.String{Data: "WQL"},
		Query:         &oaut.String{Data: query},
		Flags:         int32(flags),
	}, dcom.WithIPID(login.Namespace.InterfacePointer().IPID()))
	if err != nil {
		return fmt.Errorf("IWbemServices.ExecQuery: %w", err)
	}

	if !forward {
		_, err = wmiCli.EnumClassObject().Reset(ctx, &ienumwbemclassobject.ResetRequest{
			This: &dcom.ORPCThis{Version: srv.COMVersion},
		}, dcom.WithIPID(enum.Enum.InterfacePointer().IPID()))
		if err != nil {
			return fmt.Errorf("IEnumWbemClassObject.Reset: %w", err)
		}
	}

	qif, err := wmiCli.RemoteUnknown2().RemoteQueryInterface2(ctx, &iremunknown2.RemoteQueryInterface2Request{
		This: &dcom.ORPCThis{Version: srv.COMVersion},
		IPID: enum.Enum.InterfacePointer().IPID().GUID(),
		IIDs: []*dcom.IID{iwbemfetchsmartenum.FetchSmartEnumIID},
	}, dcom.WithIPID(act.RemoteUnknown))
	if err != nil {
		return fmt.Errorf("RemoteQueryInterface2: %w", err)
	}

	smartenum, err := wmiCli.FetchSmartEnum().GetSmartEnum(ctx, &iwbemfetchsmartenum.GetSmartEnumRequest{
		This: &dcom.ORPCThis{Version: srv.COMVersion},
	}, dcom.WithIPID(qif.Interface[0].IPID()))
	if err != nil {
		return fmt.Errorf("IWbemFetchSmartEnum.GetSmartEnum: %w", err)
	}

	if limit > 0 && limit < page {
		page = limit
	}

	// classes should store the class definitions across the calls.
	var classes = make(map[string]*wmio.Class)

	for i := 0; limit == 0 || i < limit; i += page {

		ret, err := wmiCli.WCOSmartEnum().Next(ctx, &iwbemwcosmartenum.NextRequest{
			This:    &dcom.ORPCThis{Version: srv.COMVersion},
			Timeout: -1,
			Count:   uint32(page),
		}, dcom.WithIPID(smartenum.SmartEnum.InterfacePointer().IPID()))
		if err != nil {
			if wmi.Status(ret.Return) != wmi.StatusFalse {
				return fmt.Errorf("IWbemWcoSmartEnum.Next: %w", err)
			}
		}

		if len(ret.Buffer) == 0 {
			break
		}

		oa, err := wmi.UnmarshalObjectArrayWithClasses(ret.Buffer, classes)
		if err != nil {
			return fmt.Errorf("unmarshal_object_array_with_classes: %w", err)
		}

		for _, po := range oa.Objects {
			if po.Object.Class != nil {
				if err := writer.Encode(po.Object.Properties()); err != nil {
					return fmt.Errorf("encode properties: %w", err)
				}
			} else {
				if err := writer.Encode(trimNulls(po.Object.Values())); err != nil {
					return fmt.Errorf("encode values: %w", err)
				}
			}
		}
	}

	return nil
}

func trimNulls(values wmio.Values) wmio.Values {
	for k, v := range values {
		if v == nil {
			delete(values, k)
		}
	}
	return values
}

func newEncoder(outputFormat string) interface{ Encode(v any) error } {
	switch outputFormat {
	case "yaml":
		return yaml.NewEncoder(os.Stdout)
	default:
		writer := json.NewEncoder(os.Stdout)
		writer.SetIndent("", "  ")
		return writer
	}
}

func binaryName() string {
	executable, err := os.Executable()
	if err == nil {
		return filepath.Base(executable)
	}

	if len(os.Args) > 0 {
		return filepath.Base(os.Args[0])
	}

	return "wmiq"
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(1)
	}
}
